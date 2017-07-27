/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
    "crypto/tls"
    "errors"
    "time"
    "fmt"
    "flag"
    "encoding/json"
    "github.com/golang/glog"
    "io/ioutil"
    "net/http"
    "net/url"
    "github.com/kubernetes-incubator/external-storage/lib/controller"
    "k8s.io/client-go/pkg/api/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/wait"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "os"
    "path/filepath"
    "strings"
    "syscall"
)


const (
    resyncPeriod              = 15 * time.Second
    provisionerName           = "nexenta.com/k8s-nexentastor5-nfs"
    exponentialBackOffOnError = false
    failedRetryThreshold      = 5
    leasePeriod               = controller.DefaultLeaseDuration
    retryPeriod               = controller.DefaultRetryPeriod
    renewDeadline             = controller.DefaultRenewDeadline
    termLimit                 = controller.DefaultTermLimit
    defaultParentFilesystem   = "kubernetes"
)

type NexentaStorProvisioner struct {
    // Identity of this NexentaStorProvisioner, set to node's name. Used to identify
    // "this" provisioner's PVs.
    Identity string
    Hostname string
    Port     string
    Pool     string
    Path     string
    ParentFS string
    Endpoint string
    Auth     Auth
}

type Auth struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

func NewNexentaStorProvisioner() controller.Provisioner {
    nodeName := os.Getenv("NODE_NAME")
    if nodeName == "" {
        glog.Fatal("env variable NODE_NAME must be set so that this provisioner can identify itself")
    }
    hostname := os.Getenv("NEXENTA_HOSTNAME")
    if hostname == "" {
        glog.Fatal("env variable NEXENTA_HOSTNAME must be set to communicate with NexentaStor")
    }
    port := os.Getenv("NEXENTA_HOSTPORT")
    if port == "" {
        glog.Fatal("env variable NEXENTA_HOSTPORT must be set to communicate with NexentaStor")
    }
    pool := os.Getenv("NEXENTA_POOL")
    if pool == "" {
        glog.Fatal("env variable NEXENTA_POOL must be set")
    }
    username := os.Getenv("NEXENTA_USERNAME")
    if username == "" {
        glog.Fatal("env variable NEXENTA_USERNAME must be set")
    }
    password := os.Getenv("NEXENTA_PASSWORD")
    if password == "" {
        glog.Fatal("env variable NEXENTA_PASSWORD must be set")
    }
    parentFS := os.Getenv("NEXENTA_PARENT_FILESYSTEM")
    if parentFS == "" {
        parentFS = defaultParentFilesystem
    }
    auth := Auth{Username: username, Password: password}
    p:= &NexentaStorProvisioner{
        Identity: nodeName,
        Hostname: hostname,
        Port:     port,
        Pool:     pool,
        ParentFS: parentFS,
        Path:     filepath.Join(pool, parentFS),
        Auth:     auth,
        Endpoint: fmt.Sprintf("https://%s:%s/", hostname, port),
    }
    p.Initialize()
    return p
}

func (p *NexentaStorProvisioner) Initialize() {
    data := map[string]interface{} {
        "path": filepath.Join(p.Path),
    }
    _, err:= p.Request("POST", "storage/filesystems", data)
    if (err != nil) {
        glog.Fatal("Failed to Initialize NexentaStor NFS plugin.")
    }
}

// Provision creates a storage asset and returns a PV object representing it.
func (p *NexentaStorProvisioner) Provision(options controller.VolumeOptions) (pv *v1.PersistentVolume, err error) {
    glog.Infof("Creating volume %s", options.PVName)
    data := map[string]interface{} {
        "path": filepath.Join(p.Path, options.PVName),
    }
    p.Request("POST", "storage/filesystems", data)

    data = make(map[string]interface{})
    data["anon"] = "root"
    data["filesystem"] = filepath.Join(p.Path, options.PVName)
    glog.Infof("Options: %s", options)
    // data["quotaSize"] = options.Size
    p.Request("POST", "nas/nfs", data)
    url := "storage/filesystems/" + p.Pool + "%2F" + p.ParentFS + "%2F" + options.PVName
    resp, err := p.Request("GET", url, nil)
    r := make(map[string]interface{})
    jsonerr := json.Unmarshal(resp, &r)
    if (jsonerr != nil) {
        glog.Fatal(jsonerr)
    }
    pv = &v1.PersistentVolume{
        ObjectMeta: metav1.ObjectMeta{
            Name: options.PVName,
            Annotations: map[string]string{
                "nexentaStorProvisionerIdentity": p.Identity,
            },
        },
        Spec: v1.PersistentVolumeSpec{
            PersistentVolumeReclaimPolicy: options.PersistentVolumeReclaimPolicy,
            AccessModes:                   options.PVC.Spec.AccessModes,
            Capacity: v1.ResourceList{
                v1.ResourceName(v1.ResourceStorage): options.PVC.Spec.Resources.Requests[v1.ResourceName(v1.ResourceStorage)],
            },
            PersistentVolumeSource: v1.PersistentVolumeSource{
                NFS: &v1.NFSVolumeSource{
                    Server:   p.Hostname,
                    Path:     r["mountPoint"].(string),
                    ReadOnly: false,
                },
            },
        },
    }
    return 
}

// Delete removes the storage asset that was created by Provision represented
// by the given PV.
func (p *NexentaStorProvisioner) Delete(volume *v1.PersistentVolume) error {
    path := volume.Spec.PersistentVolumeSource.NFS.Path[1:]
    glog.Info("Deleting Volume ", path)
    body, err := p.Request("DELETE",  filepath.Join("storage/filesystems/", url.QueryEscape(path)), nil)
    if strings.Contains(string(body), "ENOENT") {
        glog.Info("Error trying to delete volume ", path, " :", err)
    }
    return nil
}

func (p *NexentaStorProvisioner) Request(method, endpoint string, data map[string]interface{}) (body []byte, err error) {
    glog.Info("Issue request to Nexenta, endpoint: ", endpoint, " data: ", data, " method: ", method)
    if p.Endpoint == "" {
        glog.Error("Endpoint is not set, unable to issue requests")
        err = errors.New("Unable to issue json-rpc requests without specifying Endpoint")
        return nil, err
    }
    datajson, err := json.Marshal(data)
    if (err != nil) {
        glog.Error(err)
    }
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    url := p.Endpoint + endpoint
    req, err := http.NewRequest(method, url, nil)
    if len(data) != 0 {
        req, err = http.NewRequest(method, url, strings.NewReader(string(datajson)))
    }
    if (err != nil) {
        glog.Error(err)
    }
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if resp.Status == "" {
        err = errors.New("Empty response from NexentaStor, check appliance availability.")
        glog.Fatal(err)
        return
    }
    glog.Info("No auth: ", resp.StatusCode, resp.Body)
    if resp.StatusCode == 401 || resp.StatusCode == 403 {
        auth, err := p.https_auth()
        if err != nil {
            glog.Error("Error while trying to https login: %s", err)
            return nil, err
        }
        req, err = http.NewRequest(method, url, nil)
        if len(data) != 0 {
            req, err = http.NewRequest(method, url, strings.NewReader(string(datajson)))
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
        resp, err = client.Do(req)
        glog.Info("With auth: ", resp.StatusCode, resp.Body)
    }

    if err != nil {
        glog.Error("Error while handling request %s", err)
        return nil, err
    }
    p.checkError(resp)
    defer resp.Body.Close()
    body, err = ioutil.ReadAll(resp.Body)
    if (err != nil) {
        glog.Error(err)
    }
    if (resp.StatusCode == 202) {
        body, err = p.resend202(body)
    }
    return body, err
}

func (p *NexentaStorProvisioner) https_auth() (token string, err error){
    data := map[string]string {
        "username": p.Auth.Username,
        "password": p.Auth.Password,
    }
    datajson, err := json.Marshal(data)
    url := p.Endpoint + "auth/login"
    req, err := http.NewRequest("POST", url, strings.NewReader(string(datajson)))
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    glog.Info(resp.StatusCode, resp.Body)

    if err != nil {
        glog.Error("Error while handling request: %s", err)
        return "", err
    }
    p.checkError(resp)
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if (err != nil) {
        glog.Error(err)
    }
    r := make(map[string]interface{})
    err = json.Unmarshal(body, &r)
    if (err != nil) {
        err = fmt.Errorf("Error while trying to unmarshal json: %s", err)
        return "", err
    }
    return r["token"].(string), err
}

func (p *NexentaStorProvisioner) resend202(body []byte) ([]byte, error) {
    time.Sleep(1000 * time.Millisecond)
    r := make(map[string][]map[string]string)
    err := json.Unmarshal(body, &r)
    if (err != nil) {
        err = fmt.Errorf("Error while trying to unmarshal json %s", err)
        return body, err
    }

    url := p.Endpoint + r["links"][0]["href"]
    req, err := http.NewRequest("GET", url, nil)
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
        err = fmt.Errorf("Error while handling request %s", err)
        return body, err
    }
    defer resp.Body.Close()
    p.checkError(resp)

    if resp.StatusCode == 202 {
        body, err = p.resend202(body)
    }
    body, err = ioutil.ReadAll(resp.Body)
    return body, err
}

func (p *NexentaStorProvisioner) checkError(resp *http.Response) (err error) {
    if resp.StatusCode > 401 {
        body, err := ioutil.ReadAll(resp.Body)
        err = fmt.Errorf("Got error in response from Nexenta, status_code: %s, body: %s", resp.StatusCode, string(body))
        return err
    }
    return err
}

func main() {
    flag.Parse()
    flag.Set("logtostderr", "true")
    
    syscall.Umask(0)

    // Create an InClusterConfig and use it to create a client for the controller
    // to use to communicate with Kubernetes
    config, err := rest.InClusterConfig()
    if err != nil {
        glog.Fatalf("Failed to create config: %v", err)
    }
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        glog.Fatalf("Failed to create client: %v", err)
    }

    // The controller needs to know what the server version is because out-of-tree
    // provisioners aren't officially supported until 1.5
    serverVersion, err := clientset.Discovery().ServerVersion()
    if err != nil {
        glog.Fatalf("Error getting server version: %v", err)
    }

    // Create the provisioner: it implements the Provisioner interface expected by
    // the controller
    nexentaStorProvisioner := NewNexentaStorProvisioner()

    // Start the provision controller which will dynamically provision nexentaStor
    // PVs
    pc := controller.NewProvisionController(clientset, provisionerName, nexentaStorProvisioner, serverVersion.GitVersion)
    pc.Run(wait.NeverStop)
}
