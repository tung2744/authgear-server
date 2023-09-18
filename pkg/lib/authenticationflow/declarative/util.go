package declarative

import (
	"context"
	"fmt"

	"github.com/authgear/authgear-server/pkg/api/apierrors"
	"github.com/authgear/authgear-server/pkg/api/model"
	authflow "github.com/authgear/authgear-server/pkg/lib/authenticationflow"
	"github.com/authgear/authgear-server/pkg/lib/authn/authenticator"
	"github.com/authgear/authgear-server/pkg/lib/authn/identity"
	"github.com/authgear/authgear-server/pkg/lib/authn/mfa"
	"github.com/authgear/authgear-server/pkg/lib/config"
	"github.com/authgear/authgear-server/pkg/util/errorutil"
)

func authenticatorIsDefault(deps *authflow.Dependencies, userID string, authenticatorKind model.AuthenticatorKind) (isDefault bool, err error) {
	ais, err := deps.Authenticators.List(
		userID,
		authenticator.KeepKind(authenticatorKind),
		authenticator.KeepDefault,
	)
	if err != nil {
		return
	}

	isDefault = len(ais) == 0
	return
}

func flowRootObject(deps *authflow.Dependencies, flowReference authflow.FlowReference) (config.AuthenticationFlowObject, error) {
	switch flowReference.Type {
	case authflow.FlowTypeSignup:
		return flowRootObjectForSignupFlow(deps, flowReference)
	case authflow.FlowTypeLogin:
		return flowRootObjectForLoginFlow(deps, flowReference)
	default:
		panic(fmt.Errorf("unexpected flow type: %v", flowReference.Type))
	}
}

func flowRootObjectForSignupFlow(deps *authflow.Dependencies, flowReference authflow.FlowReference) (config.AuthenticationFlowObject, error) {
	var root config.AuthenticationFlowObject

	if flowReference.ID == idGeneratedFlow {
		root = GenerateSignupFlowConfig(deps.Config)
	} else {
		for _, f := range deps.Config.AuthenticationFlow.SignupFlows {
			f := f
			if f.ID == flowReference.ID {
				root = f
				break
			}
		}

	}

	if root == nil {
		return nil, ErrFlowNotFound
	}

	return root, nil
}

func flowRootObjectForLoginFlow(deps *authflow.Dependencies, flowReference authflow.FlowReference) (config.AuthenticationFlowObject, error) {
	var root config.AuthenticationFlowObject

	if flowReference.ID == idGeneratedFlow {
		root = GenerateLoginFlowConfig(deps.Config)
	} else {
		for _, f := range deps.Config.AuthenticationFlow.LoginFlows {
			f := f
			if f.ID == flowReference.ID {
				root = f
				break
			}
		}
	}

	if root == nil {
		return nil, ErrFlowNotFound
	}

	return root, nil
}

func getAuthenticationCandidatesForStep(ctx context.Context, deps *authflow.Dependencies, flows authflow.Flows, userID string, step *config.AuthenticationFlowLoginFlowStep) ([]UseAuthenticationCandidate, error) {
	candidates := []UseAuthenticationCandidate{}

	infos, err := deps.Authenticators.List(userID)
	if err != nil {
		return nil, err
	}

	recoveryCodes, err := deps.MFA.ListRecoveryCodes(userID)
	if err != nil {
		return nil, err
	}

	byTarget := func(am config.AuthenticationFlowAuthentication, targetStepID string) error {
		// Find the target step from the root.
		targetStepFlow, err := FindTargetStep(flows.Root, targetStepID)
		if err != nil {
			return err
		}

		target, ok := targetStepFlow.Intent.(IntentLoginFlowStepAuthenticateTarget)
		if !ok {
			return InvalidTargetStep.NewWithInfo("invalid target_step", apierrors.Details{
				"target_step": targetStepID,
			})
		}

		identityInfo := target.GetIdentity(ctx, deps, flows.Replace(targetStepFlow))

		allAllowed := []config.AuthenticationFlowAuthentication{am}
		filteredInfos := authenticator.ApplyFilters(infos, KeepAuthenticationMethod(am), IsDependentOf(identityInfo))
		moreCandidates, err := getAuthenticationCandidates(deps.Config.Authenticator.OOB, filteredInfos, recoveryCodes, allAllowed)
		if err != nil {
			return err
		}

		candidates = append(candidates, moreCandidates...)
		return nil
	}

	byUser := func(am config.AuthenticationFlowAuthentication) error {
		allAllowed := []config.AuthenticationFlowAuthentication{am}
		filteredInfos := authenticator.ApplyFilters(infos, KeepAuthenticationMethod(allAllowed...))
		moreCandidates, err := getAuthenticationCandidates(deps.Config.Authenticator.OOB, filteredInfos, recoveryCodes, allAllowed)
		if err != nil {
			return err
		}
		candidates = append(candidates, moreCandidates...)
		return nil
	}

	for _, branch := range step.OneOf {
		switch branch.Authentication {
		case config.AuthenticationFlowAuthenticationDeviceToken:
			// Device token is handled transparently.
			break

		case config.AuthenticationFlowAuthenticationRecoveryCode:

		case config.AuthenticationFlowAuthenticationPrimaryPassword:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryPassword:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryTOTP:
			err := byUser(branch.Authentication)
			if err != nil {
				return nil, err
			}

		case config.AuthenticationFlowAuthenticationPrimaryOOBOTPEmail:
			fallthrough
		case config.AuthenticationFlowAuthenticationPrimaryOOBOTPSMS:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryOOBOTPEmail:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryOOBOTPSMS:
			if targetStepID := branch.TargetStep; targetStepID != "" {
				err := byTarget(branch.Authentication, targetStepID)
				if err != nil {
					return nil, err
				}
			} else {
				err := byUser(branch.Authentication)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return candidates, nil
}

func getAuthenticationCandidates(oobConfig *config.AuthenticatorOOBConfig, as []*authenticator.Info, recoveryCodes []*mfa.RecoveryCode, allAllowed []config.AuthenticationFlowAuthentication) (allUsable []UseAuthenticationCandidate, err error) {
	addPasswordAlways := func(am config.AuthenticationFlowAuthentication) {
		count := len(as)
		allUsable = append(allUsable, NewUseAuthenticationCandidatePassword(am, count))
	}

	addOneIfPresent := func() {
		added := false
		for _, a := range as {
			candidate := NewUseAuthenticationCandidateFromInfo(oobConfig, a)
			if !added {
				allUsable = append(allUsable, candidate)
				added = true
			}
		}
	}

	addAll := func() {
		for _, a := range as {
			candidate := NewUseAuthenticationCandidateFromInfo(oobConfig, a)
			allUsable = append(allUsable, candidate)
		}
	}

	addRecoveryCodeIfPresent := func() {
		if len(recoveryCodes) > 0 {
			allUsable = append(allUsable, NewUseAuthenticationCandidateRecoveryCode())
		}
	}

	for _, allowed := range allAllowed {
		switch allowed {
		case config.AuthenticationFlowAuthenticationPrimaryPassword:
			addPasswordAlways(allowed)
		case config.AuthenticationFlowAuthenticationSecondaryPassword:
			addOneIfPresent()
		case config.AuthenticationFlowAuthenticationPrimaryOOBOTPEmail:
			fallthrough
		case config.AuthenticationFlowAuthenticationPrimaryOOBOTPSMS:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryOOBOTPEmail:
			fallthrough
		case config.AuthenticationFlowAuthenticationSecondaryOOBOTPSMS:
			addAll()
		case config.AuthenticationFlowAuthenticationSecondaryTOTP:
			addOneIfPresent()
		case config.AuthenticationFlowAuthenticationRecoveryCode:
			addRecoveryCodeIfPresent()
		case config.AuthenticationFlowAuthenticationDeviceToken:
			// Device token is handled transparently.
			break
		}
	}

	return
}

func identityFillDetails(err error, spec *identity.Spec, otherSpec *identity.Spec) error {
	details := errorutil.Details{}

	if spec != nil {
		details["IdentityTypeIncoming"] = apierrors.APIErrorDetail.Value(spec.Type)
		switch spec.Type {
		case model.IdentityTypeLoginID:
			details["LoginIDTypeIncoming"] = apierrors.APIErrorDetail.Value(spec.LoginID.Type)
		case model.IdentityTypeOAuth:
			details["OAuthProviderTypeIncoming"] = apierrors.APIErrorDetail.Value(spec.OAuth.ProviderID.Type)
		}
	}

	if otherSpec != nil {
		details["IdentityTypeExisting"] = apierrors.APIErrorDetail.Value(otherSpec.Type)
		switch otherSpec.Type {
		case model.IdentityTypeLoginID:
			details["LoginIDTypeExisting"] = apierrors.APIErrorDetail.Value(otherSpec.LoginID.Type)
		case model.IdentityTypeOAuth:
			details["OAuthProviderTypeExisting"] = apierrors.APIErrorDetail.Value(otherSpec.OAuth.ProviderID.Type)
		}
	}

	return errorutil.WithDetails(err, details)
}

func getChannels(claimName model.ClaimName, oobConfig *config.AuthenticatorOOBConfig) []model.AuthenticatorOOBChannel {
	email := false
	sms := false
	whatsapp := false

	switch claimName {
	case model.ClaimEmail:
		email = true
	case model.ClaimPhoneNumber:
		switch oobConfig.SMS.PhoneOTPMode {
		case config.AuthenticatorPhoneOTPModeSMSOnly:
			sms = true
		case config.AuthenticatorPhoneOTPModeWhatsappOnly:
			whatsapp = true
		case config.AuthenticatorPhoneOTPModeWhatsappSMS:
			sms = true
			whatsapp = true
		}
	}

	channels := []model.AuthenticatorOOBChannel{}
	if email {
		channels = append(channels, model.AuthenticatorOOBChannelEmail)
	}
	if sms {
		channels = append(channels, model.AuthenticatorOOBChannelSMS)
	}
	if whatsapp {
		channels = append(channels, model.AuthenticatorOOBChannelWhatsapp)
	}

	return channels
}