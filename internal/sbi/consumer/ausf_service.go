package consumer

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/openapi"
	Nausf_UEAuthentication "github.com/free5gc/openapi/ausf/UEAuthentication"
	"github.com/free5gc/openapi/models"
)

type nausfService struct {
	consumer *Consumer

	UEAuthenticationMu sync.RWMutex

	UEAuthenticationClients map[string]*Nausf_UEAuthentication.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *Nausf_UEAuthentication.APIClient {
	if uri == "" {
		return nil
	}
	s.UEAuthenticationMu.RLock()
	client, ok := s.UEAuthenticationClients[uri]
	if ok {
		s.UEAuthenticationMu.RUnlock()
		return client
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nausf_UEAuthentication.NewAPIClient(configuration)

	s.UEAuthenticationMu.RUnlock()
	s.UEAuthenticationMu.Lock()
	defer s.UEAuthenticationMu.Unlock()
	s.UEAuthenticationClients[uri] = client
	return client
}

func (s *nausfService) SendUEAuthenticationAuthenticateRequest(ue *amf_context.AmfUe,
	resynchronizationInfo *models.ResynchronizationInfo,
) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {
	client := s.getUEAuthenticationClient(ue.AusfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	amfSelf := amf_context.GetSelf()

	// Find matching PLMN from servedGuamiList
	var servedGuami models.Guami
	found := false

	logger.ConsumerLog.Infof("WNC: Starting PLMN matching for UE authentication - UE PLMN: MCC=%s, MNC=%s", ue.PlmnId.Mcc, ue.PlmnId.Mnc)
	logger.ConsumerLog.Infof("WNC: Available servedGuamiList has %d entries", len(amfSelf.ServedGuamiList))

	for i, guami := range amfSelf.ServedGuamiList {
		logger.ConsumerLog.Debugf("WNC: Checking servedGuamiList[%d]: MCC=%s, MNC=%s", i, guami.PlmnId.Mcc, guami.PlmnId.Mnc)
		
		if ue.PlmnId.Mcc != "" && ue.PlmnId.Mnc != "" &&
		   guami.PlmnId.Mcc == ue.PlmnId.Mcc && guami.PlmnId.Mnc == ue.PlmnId.Mnc {
			servedGuami = guami
			found = true
			logger.ConsumerLog.Infof("WNC: Found matching PLMN at servedGuamiList[%d]: MCC=%s, MNC=%s", i, guami.PlmnId.Mcc, guami.PlmnId.Mnc)
			break
		}
	}

	if !found {
		servedGuami = amfSelf.ServedGuamiList[0] // fallback
		logger.ConsumerLog.Warnf("WNC: No matching PLMN found for UE (MCC=%s, MNC=%s), using servedGuamiList[0]: MCC=%s, MNC=%s", 
			ue.PlmnId.Mcc, ue.PlmnId.Mnc, servedGuami.PlmnId.Mcc, servedGuami.PlmnId.Mnc)
	}

	var authInfo models.AuthenticationInfo
	authInfo.SupiOrSuci = ue.Suci
	if mnc, err := strconv.Atoi(servedGuami.PlmnId.Mnc); err != nil {
		logger.ConsumerLog.Errorf("WNC: Failed to parse MNC '%s' as integer: %v", servedGuami.PlmnId.Mnc, err)
		return nil, nil, err
	} else {
		authInfo.ServingNetworkName = fmt.Sprintf("5G:mnc%03d.mcc%s.3gppnetwork.org", mnc, servedGuami.PlmnId.Mcc)
			logger.ConsumerLog.Infof("WNC: Generated ServingNetworkName: %s", authInfo.ServingNetworkName)
	}
	if resynchronizationInfo != nil {
		authInfo.ResynchronizationInfo = resynchronizationInfo
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	authReq := Nausf_UEAuthentication.UeAuthenticationsPostRequest{
		AuthenticationInfo: &authInfo,
	}

	res, localErr := client.DefaultApi.UeAuthenticationsPost(ctx, &authReq)
	if localErr == nil {
		return &res.UeAuthenticationCtx, nil, nil
	} else {
		switch errType := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nausf_UEAuthentication.UeAuthenticationsPostError:
				return nil, &errModel.ProblemDetails, localErr
			case error:
				return nil, openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, nil, openapi.ReportError("openapi error")
			}
		case error:
			return nil, openapi.ProblemDetailsSystemFailure(errType.Error()), err
		default:
			return nil, nil, openapi.ReportError("server no response")
		}
	}
}

func (s *nausfService) SendAuth5gAkaConfirmRequest(ue *amf_context.AmfUe, resStar string) (
	*models.ConfirmationDataResponse, *models.ProblemDetails, error,
) {
	var ausfUri string
	var confirmUri *url.URL
	var err error
	if len(ue.AuthenticationCtx.Links["5g-aka"]) > 0 {
		confirmUri, err = url.Parse(ue.AuthenticationCtx.Links["5g-aka"][0].Href)
	}
	if err != nil {
		return nil, nil, err
	} else {
		ausfUri = fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)
	}

	client := s.getUEAuthenticationClient(ausfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}
	// confirmUri.RequestURI() = "/nausf-auth/v1/ue-authentications/{authctxId}/5g-aka-confirmation"
	// splituri = ["","nausf-auth","ue-authentications",{authctxId},"5g-aka-confirmation"]
	// authctxId = {authctxId}
	splituri := strings.Split(confirmUri.RequestURI(), "/")
	authctxId := ""
	if len(splituri) > 4 {
		authctxId = splituri[4]
	} else {
		return nil, nil, fmt.Errorf("authctxId is nil")
	}

	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutRequest{
		AuthCtxId: &authctxId,
		ConfirmationData: &models.ConfirmationData{
			ResStar: resStar,
		},
	}
	confirmResult, localErr := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		ctx, confirmData)
	if localErr == nil {
		return &confirmResult.ConfirmationDataResponse, nil, nil
	} else {
		switch err := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := err.Model().(type) {
			case Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutError:
				return nil, &errModel.ProblemDetails, localErr
			case error:
				return nil, openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, nil, openapi.ReportError("openapi error")
			}
		case error:
			return nil, openapi.ProblemDetailsSystemFailure(err.Error()), nil
		default:
			return nil, nil, openapi.ReportError("server no response")
		}
	}
}

func (s *nausfService) SendEapAuthConfirmRequest(ue *amf_context.AmfUe, eapMsg nasType.EAPMessage) (
	response *models.EapSession, problemDetails *models.ProblemDetails, err1 error,
) {
	var confirmUri *url.URL
	var err error
	if len(ue.AuthenticationCtx.Links["eap-session"]) > 0 {
		confirmUri, err = url.Parse(ue.AuthenticationCtx.Links["eap-session"][0].Href)
	}
	if err != nil {
		logger.ConsumerLog.Errorf("url Parse failed: %+v", err)
	}
	ausfUri := fmt.Sprintf("%s://%s", confirmUri.Scheme, confirmUri.Host)

	client := s.getUEAuthenticationClient(ausfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	// confirmUri.RequestURI() = "/nausf-auth/v1/ue-authentications/{authctxId}/eap-session"
	// splituri = ["","nausf-auth","ue-authentications",{authctxId},"eap-session"]
	// authctxId = {authctxId}
	splituri := strings.Split(confirmUri.RequestURI(), "/")
	authctxId := ""
	if len(splituri) > 4 {
		authctxId = splituri[4]
	} else {
		return nil, nil, fmt.Errorf("authctxId is nil")
	}

	eapSessionReq := Nausf_UEAuthentication.EapAuthMethodRequest{
		AuthCtxId: &authctxId,
		EapSession: &models.EapSession{
			EapPayload: base64.StdEncoding.EncodeToString(eapMsg.GetEAPMessage()),
		},
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NrfNfManagementNfType_AUSF)
	if err != nil {
		return nil, nil, err
	}

	eapSession, localErr := client.DefaultApi.EapAuthMethod(ctx, &eapSessionReq)

	if localErr == nil {
		response = &eapSession.EapSession
	} else {
		err = localErr
		switch errType := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nausf_UEAuthentication.EapAuthMethodError:
				problemDetails = &errModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(errType.Error())
		default:
			err = openapi.ReportError("server no response")
		}
	}

	return response, problemDetails, err
}
