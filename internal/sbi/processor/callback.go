package processor

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	gmm_message "github.com/free5gc/amf/internal/gmm/message"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/internal/policy"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

func (p *Processor) HandleSmContextStatusNotify(c *gin.Context,
	smContextStatusNotification models.SmfPduSessionSmContextStatusNotification,
) {
	logger.ProducerLog.Infoln("[AMF] Handle SmContext Status Notify")

	supi := c.Param("supi")
	pduSessionIDString := c.Param("pduSessionId")
	var pduSessionID int
	if pduSessionIDTmp, err := strconv.Atoi(pduSessionIDString); err != nil {
		logger.ProducerLog.Warnf("PDU Session ID atoi failed: %+v", err)
	} else {
		pduSessionID = pduSessionIDTmp
	}

	problemDetails := p.SmContextStatusNotifyProcedure(supi, int32(pduSessionID), smContextStatusNotification)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) SmContextStatusNotifyProcedure(supi string, pduSessionID int32,
	smContextStatusNotification models.SmfPduSessionSmContextStatusNotification,
) *models.ProblemDetails {
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindBySupi(supi)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Supi[%s] Not Found", supi),
		}
		return problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	smContext, ok := ue.SmContextFindByPDUSessionID(pduSessionID)
	if !ok {
		ue.ProducerLog.Errorf("SmContext[PDU Session ID:%d] not found", pduSessionID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("PDUSessionID[%d] Not Found", pduSessionID),
		}
		return problemDetails
	}

	if smContextStatusNotification.StatusInfo.ResourceStatus == models.ResourceStatus_RELEASED {
		if smContext.PduSessionIDDuplicated() {
			ue.ProducerLog.Infof("Local release duplicated SmContext[%d]", pduSessionID)
			smContext.SetDuplicatedPduSessionID(false)
		} else {
			ue.ProducerLog.Infof("Release SmContext[%d] (Cause: %s)", pduSessionID,
				smContextStatusNotification.StatusInfo.Cause)
		}
		ue.SmContextList.Delete(pduSessionID)
	} else {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "INVALID_MSG_FORMAT",
			InvalidParams: []models.InvalidParam{
				{Param: "StatusInfo.ResourceStatus", Reason: "invalid value"},
			},
		}
		return problemDetails
	}
	return nil
}

func (p *Processor) HandleAmPolicyControlUpdateNotifyUpdate(c *gin.Context,
	policyUpdate models.PcfAmPolicyControlPolicyUpdate,
) {
	logger.ProducerLog.Infoln("Handle AM Policy Control Update Notify [Policy update notification]")

	polAssoID := c.Param("polAssoId")
	problemDetails := p.AmPolicyControlUpdateNotifyUpdateProcedure(polAssoID, policyUpdate)

	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) AmPolicyControlUpdateNotifyUpdateProcedure(polAssoID string,
	policyUpdate models.PcfAmPolicyControlPolicyUpdate,
) *models.ProblemDetails {
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindByPolicyAssociationID(polAssoID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Policy Association ID[%s] Not Found", polAssoID),
		}
		return problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	ue.AmPolicyAssociation.Triggers = policyUpdate.Triggers
	ue.RequestTriggerLocationChange = false

	for _, trigger := range policyUpdate.Triggers {
		if trigger == models.PcfAmPolicyControlRequestTrigger_LOC_CH {
			ue.RequestTriggerLocationChange = true
		}
		// if trigger == models.RequestTrigger_PRA_CH {
		// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
		// }
	}

	if policyUpdate.ServAreaRes != nil {
		ue.AmPolicyAssociation.ServAreaRes = policyUpdate.ServAreaRes
	}

	if policyUpdate.Rfsp != 0 {
		ue.AmPolicyAssociation.Rfsp = policyUpdate.Rfsp
	}

	if ue != nil {
		// use go routine to write response first to ensure the order of the procedure
		go func() {
			defer func() {
				if p := recover(); p != nil {
					// Print stack for panic to log. Fatalf() will let program exit.
					logger.CallbackLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
				}
			}()

			configurationUpdateCommandFlags := &context.ConfigurationUpdateCommandFlags{
				NeedGUTI:            true,
				NeedAllowedNSSAI:    true,
				NeedConfiguredNSSAI: true,
				NeedRejectNSSAI:     true,
				NeedTaiList:         true,
				NeedNITZ:            true,
				NeedLadnInformation: true,
			}

			// UE is CM-Connected State
			if ue.CmConnect(models.AccessType__3_GPP_ACCESS) {
				gmm_message.SendConfigurationUpdateCommand(ue,
					models.AccessType__3_GPP_ACCESS,
					configurationUpdateCommandFlags,
				)
			} else {
				// UE is CM-IDLE => paging
				ue.ConfigurationUpdateCommandFlags = configurationUpdateCommandFlags

				ue.SetOnGoing(models.AccessType__3_GPP_ACCESS, &context.OnGoing{
					Procedure: context.OnGoingProcedurePaging,
				})

				pkg, err := ngap_message.BuildPaging(ue, nil, false)
				if err != nil {
					logger.NgapLog.Errorf("Build Paging failed : %s", err.Error())
					return
				}
				ngap_message.SendPaging(ue, pkg)
			}
		}()
	}
	return nil
}

// TS 29.507 4.2.4.3
func (p *Processor) HandleAmPolicyControlUpdateNotifyTerminate(c *gin.Context,
	terminationNotification models.PcfAmPolicyControlTerminationNotification,
) {
	logger.ProducerLog.Infoln("Handle AM Policy Control Update Notify [Request for termination of the policy association]")

	polAssoID := c.Param("polAssoId")

	problemDetails := p.AmPolicyControlUpdateNotifyTerminateProcedure(polAssoID, terminationNotification)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) AmPolicyControlUpdateNotifyTerminateProcedure(polAssoID string,
	terminationNotification models.PcfAmPolicyControlTerminationNotification,
) *models.ProblemDetails {
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindByPolicyAssociationID(polAssoID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Policy Association ID[%s] Not Found", polAssoID),
		}
		return problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	logger.CallbackLog.Infof("Cause of AM Policy termination[%+v]", terminationNotification.Cause)

	// use go routine to write response first to ensure the order of the procedure
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.CallbackLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		problem, err := p.Consumer().AMPolicyControlDelete(ue)
		if problem != nil {
			logger.ProducerLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problem)
		} else if err != nil {
			logger.ProducerLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
		}
	}()
	return nil
}

// TS 23.502 4.2.2.2.3 Registration with AMF re-allocation
func (p *Processor) HandleN1MessageNotify(c *gin.Context, n1MessageNotify models.N1MessageNotifyRequest) {
	logger.ProducerLog.Infoln("[AMF] Handle N1 Message Notify")

	problemDetails := p.N1MessageNotifyProcedure(n1MessageNotify)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) N1MessageNotifyProcedure(n1MessageNotify models.N1MessageNotifyRequest) *models.ProblemDetails {
	logger.ProducerLog.Debugf("n1MessageNotify: %+v", n1MessageNotify)

	amfSelf := context.GetSelf()

	registrationCtxtContainer := n1MessageNotify.JsonData.RegistrationCtxtContainer
	if registrationCtxtContainer == nil || registrationCtxtContainer.UeContext == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING", // Defined in TS 29.500 5.2.7.2
			Detail: "Missing IE [UeContext] in RegistrationCtxtContainer",
		}
		return problemDetails
	}

	ran, ok := amfSelf.AmfRanFindByRanID(*registrationCtxtContainer.RanNodeId)
	if !ok {
		logger.CallbackLog.Warnln("AmfRanFindByRanID not found: ", *registrationCtxtContainer.RanNodeId)

		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_INCORRECT",
			Detail: fmt.Sprintf("Can not find RAN[RanId: %+v]", *registrationCtxtContainer.RanNodeId),
		}
		return problemDetails
	}

	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Print stack for panic to log. Fatalf() will let program exit.
				logger.CallbackLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			}
		}()

		var amfUe *context.AmfUe
		ueContext := registrationCtxtContainer.UeContext
		if ueContext.Supi != "" {
			amfUe = amfSelf.NewAmfUe(ueContext.Supi)
		} else {
			amfUe = amfSelf.NewAmfUe("")
		}

		amfUe.Lock.Lock()
		defer amfUe.Lock.Unlock()

		amfUe.CopyDataFromUeContextModel(ueContext)

		ranUe := ran.RanUeFindByRanUeNgapID(int64(registrationCtxtContainer.AnN2ApId))

		ranUe.Location = *registrationCtxtContainer.UserLocation
		amfUe.Location = *registrationCtxtContainer.UserLocation
		ranUe.UeContextRequest = registrationCtxtContainer.UeContextRequest
		ranUe.OldAmfName = registrationCtxtContainer.InitialAmfName

		if registrationCtxtContainer.AllowedNssai != nil {
			allowedNssai := registrationCtxtContainer.AllowedNssai
			amfUe.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}

		if len(registrationCtxtContainer.ConfiguredNssai) > 0 {
			amfUe.ConfiguredNssai = registrationCtxtContainer.ConfiguredNssai
		}

		gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)

		amf_nas.HandleNAS(ranUe, ngapType.ProcedureCodeInitialUEMessage, n1MessageNotify.BinaryDataN1Message, true)
	}()
	return nil
}

func (p *Processor) HandleUePolicyControlUpdateNotify(c *gin.Context,
	policyUpdate models.PcfUePolicyControlPolicyUpdate,
) {
	logger.ProducerLog.Info("WNC: Handle UE Policy Control Update Notify [Policy update notification]")

	uePolicyAssociationId := c.Param("uePolicyAssociationId")
	problemDetails := p.UePolicyControlUpdateNotifyProcedure(uePolicyAssociationId, policyUpdate)

	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) UePolicyControlUpdateNotifyProcedure(uePolicyAssociationId string,
	policyUpdate models.PcfUePolicyControlPolicyUpdate,
) *models.ProblemDetails {
	logger.ProducerLog.Infof("WNC: Processing UE Policy Update for Association ID: %s", uePolicyAssociationId)
	
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindByUePolicyAssociationID(uePolicyAssociationId)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("UE Policy Association ID[%s] Not Found", uePolicyAssociationId),
		}
		logger.ProducerLog.Errorf("WNC: %s", problemDetails.Detail)
		return problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	logger.ProducerLog.Infof("WNC: Found UE %s for policy update", ue.Supi)

	// Update UE Policy Association with received policy information
	if policyUpdate.UePolicy != "" {
		ue.UePolicyAssociation.UePolicy = policyUpdate.UePolicy
		logger.ProducerLog.Infof("WNC: Updated UE Policy for UE %s", ue.Supi)
	}

	// Use goroutine to send policy to UE without blocking HTTP response
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.CallbackLog.Fatalf("WNC: panic in UE policy delivery: %v\n%s", r, string(debug.Stack()))
			}
		}()

		p.SendUEPolicyToUE(ue, policyUpdate)
	}()

	return nil
}

func (p *Processor) SendUEPolicyToUE(ue *context.AmfUe, policyUpdate models.PcfUePolicyControlPolicyUpdate) {
	logger.ProducerLog.Infof("WNC: Sending UE Policy to UE %s", ue.Supi)

	if !factory.AmfConfig.Configuration.UEPolicyEnabled() {
		logger.ProducerLog.Infof("WNC: UE Policy delivery disabled by config (enableUEPolicy=false), skipping for UE %s", ue.Supi)
		return
	}

	// Check if UE is CM-Connected
	if !ue.CmConnect(models.AccessType__3_GPP_ACCESS) {
		logger.ProducerLog.Warnf("WNC: UE %s is not CM-Connected, cannot send policy", ue.Supi)
		return
	}

	ranUe := ue.RanUe[models.AccessType__3_GPP_ACCESS]
	if ranUe == nil {
		logger.ProducerLog.Errorf("WNC: RanUe is nil for UE %s", ue.Supi)
		return
	}

	// Load default policy configuration or use received policy
	var policyConfig *policy.UEPolicyConfig
	var err error
	
	if policyUpdate.UePolicy != "" {
		// TODO: Convert PCF policy to internal format
		logger.ProducerLog.Info("WNC: Using policy from PCF (conversion not yet implemented)")
		// For now, fall back to default policy
	}
	
	// Load default policy configuration
	configPath := "./config/pcfcfg_ue_policy_wnc.yaml"
	policyConfig, err = policy.LoadUEPolicyConfigFromYAML(configPath)
	if err != nil {
		logger.ProducerLog.Errorf("WNC: Failed to load UE policy config: %v", err)
		logger.ProducerLog.Info("WNC: Falling back to QXDM config")
		policyConfig = &policy.QXDMPolicyConfig
	} else {
		logger.ProducerLog.Info("WNC: Successfully loaded UE policy config from YAML")
	}

	// Send the policy command to UE
	gmm_message.SendManageUEPolicyCommand(ranUe, policyConfig)
	logger.ProducerLog.Infof("WNC: UE Policy delivered to UE %s", ue.Supi)
}
