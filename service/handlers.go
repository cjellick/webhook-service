package service

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/pborman/uuid"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/util"
	"github.com/rancher/webhook-service/config"
	"github.com/rancher/webhook-service/drivers"
	"io/ioutil"
	"net/http"
	"time"
)

type RancherClientFactory interface {
	GetClient(projectID string) (client.RancherClient, error)
}

func (rh *RouteHandler) ConstructPayload(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	webhookRequestData := make(map[string]interface{})
	userData := make(map[string]interface{})
	var url string
	logrus.Infof("Construct Payload")
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return 500, err
	}
	json.Unmarshal(bytes, &webhookRequestData)
	json.Unmarshal(bytes, &userData)

	accountID := r.Header.Get("X-API-Project-Id")
	if accountID == "" {
		return 500, fmt.Errorf("Project ID not obtained from cattle")
	}
	protocol := r.Header.Get("X-Forwarded-Proto")
	if protocol != "" {
		url = protocol + "://"
	} else {
		url = "http://"
	}
	url = url + r.Host + "/v1-webhooks-receiver?token="
	if _, ok := webhookRequestData["driver"].(string); !ok {
		return 400, fmt.Errorf("Driver of type string not provided")
	}
	driverID := webhookRequestData["driver"].(string)
	driver := drivers.GetDriver(driverID)
	if driver == nil {
		return 400, fmt.Errorf("Driver %s is not registered", driverID)
	}

	configName := driverID + "Config"
	config, ok := webhookRequestData[configName].(map[string]interface{})
	if !ok {
		return 400, fmt.Errorf("Config %s not provided for driver %s", configName, driverID)
	}
	userConfig := userData[configName].(map[string]interface{})

	apiClient, err := rh.rcf.GetClient(accountID)
	if err != nil {
		return 500, err
	}
	code, err := driver.ValidatePayload(config, apiClient)
	if err != nil {
		return code, err
	}
	config["projectId"] = accountID
	uuid := uuid.New()
	config["uuid"] = uuid
	config["driver"] = driverID
	jwt, err := util.CreateTokenWithPayload(config, PrivateKey)
	if err != nil {
		return 500, err
	}
	name, ok := webhookRequestData["name"].(string)
	if !ok {
		return 400, fmt.Errorf("Name not provided")
	}
	jwt = url + jwt

	webhook, err := saveWebhook(uuid, name, driverID, jwt, userConfig, apiClient)
	if err != nil {
		return 500, err
	}
	fmt.Printf("driver : %v\n", driver)
	apiContext.WriteResource(newWebhook(apiContext, jwt, webhook.Links, webhook.Id, driverID, name, userConfig))
	return 200, nil
}

func (rh *RouteHandler) Execute(w http.ResponseWriter, r *http.Request) (int, error) {
	jwtSigned := r.FormValue("token")
	token, err := jwt.Parse(jwtSigned, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return PublicKey, nil
	})

	if err != nil || !token.Valid {
		return 500, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if _, ok := claims["driver"].(string); !ok {
			return 500, fmt.Errorf("Driver not found after decode")
		}
		driverID := claims["driver"].(string)
		driver := drivers.GetDriver(driverID)
		if driver == nil {
			return 400, fmt.Errorf("Driver %s is not registered", driverID)
		}
		if _, ok := claims["projectId"].(string); !ok {
			return 500, fmt.Errorf("AccountId not provided by server")
		}
		projectID := claims["projectId"].(string)
		apiClient, err := rh.rcf.GetClient(projectID)
		if err != nil {
			return 500, err
		}
		uuid, ok := claims["uuid"].(string)
		if !ok {
			return 500, fmt.Errorf("Uuid not found after decode")
		}
		code, err := validateWebhook(uuid, apiClient)
		if err != nil {
			return code, err
		}

		responseCode, err := driver.Execute(claims, apiClient)
		if err != nil {
			return responseCode, fmt.Errorf("Error %v in executing driver for %s", err, driverID)
		}
	}
	return 200, nil
}

func (rh *RouteHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	projectID := r.Header.Get("X-API-Project-Id")
	if projectID == "" {
		return 500, fmt.Errorf("Project ID not obtained from cattle")
	}
	apiClient, err := rh.rcf.GetClient(projectID)
	if err != nil {
		return 500, err
	}
	webhooks, err := apiClient.Webhook.List(&client.ListOpts{})
	response := []webhook{}
	for _, webhook := range webhooks.Data {
		respWebhook := newWebhook(apiContext, webhook.Url, webhook.Links, webhook.Id, webhook.Driver, webhook.Name, webhook.Config.(map[string]interface{}))
		response = append(response, *respWebhook)
	}
	apiContext.Write(&webhookCollection{Data: response})
	return 200, nil
}

func (rh *RouteHandler) GetWebhook(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	vars := mux.Vars(r)
	webhookID := vars["id"]
	projectID := r.Header.Get("X-API-Project-Id")
	if projectID == "" {
		return 500, fmt.Errorf("Project ID not obtained from cattle")
	}
	apiClient, err := rh.rcf.GetClient(projectID)
	if err != nil {
		return 500, err
	}
	webhook, err := apiClient.Webhook.ById(webhookID)
	if err != nil {
		return 500, err
	}
	if webhook.Removed == "Revoked" {
		fmt.Printf("webhook : %v\n", webhook)
		return 400, nil
	}
	respWebhook := newWebhook(apiContext, webhook.Url, webhook.Links, webhook.Id, webhook.Driver, webhook.Name, webhook.Config.(map[string]interface{}))
	apiContext.WriteResource(respWebhook)
	return 200, nil
}

func (rh *RouteHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) (int, error) {
	vars := mux.Vars(r)
	webhookID := vars["id"]
	projectID := r.Header.Get("X-API-Project-Id")
	if projectID == "" {
		return 500, fmt.Errorf("Project ID not obtained from cattle")
	}
	apiClient, err := rh.rcf.GetClient(projectID)
	if err != nil {
		return 500, err
	}
	webhook, err := apiClient.Webhook.ById(webhookID)
	if err != nil {
		return 500, err
	}

	err = apiClient.Webhook.Delete(webhook)
	if err != nil {
		return 500, err
	}
	return 200, nil
}

func (e *ExecuteStruct) GetClient(projectID string) (client.RancherClient, error) {
	config := config.GetConfig()
	url := fmt.Sprintf("%s/projects/%s/schemas", config.CattleURL, projectID)
	apiClient, err := client.NewRancherClient(&client.ClientOpts{
		Timeout:   time.Second * 30,
		Url:       url,
		AccessKey: config.CattleAccessKey,
		SecretKey: config.CattleSecretKey,
	})
	if err != nil {
		return client.RancherClient{}, fmt.Errorf("Error in creating API client")
	}
	return *apiClient, nil
}

func saveWebhook(uuid string, name string, driver string, url string, input map[string]interface{}, apiClient client.RancherClient) (*client.Webhook, error) {
	webhook, err := apiClient.Webhook.Create(&client.Webhook{
		Name:   name,
		Key:    uuid,
		Url:    url,
		Config: input,
		Driver: driver,
	})

	if err != nil {
		return &client.Webhook{}, fmt.Errorf("Failed to create webhook : %v", err)
	}
	return webhook, nil
}

func validateWebhook(uuid string, apiClient client.RancherClient) (int, error) {
	filters := make(map[string]interface{})
	filters["key"] = uuid
	webhookCollection, err := apiClient.Webhook.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		return 500, err
	}
	if len(webhookCollection.Data) > 0 {
		return 0, nil
	}
	return 403, fmt.Errorf("Requested webhook has been revoked")
}
