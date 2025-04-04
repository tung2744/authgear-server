import React, {
  ReactNode,
  useMemo,
  useCallback,
  useState,
  useContext,
} from "react";
import cn from "classnames";
import {
  Text,
  useTheme,
  Checkbox,
  ICheckboxProps,
  Dropdown,
  DirectionalHint,
  Pivot,
  PivotItem,
  // eslint-disable-next-line no-restricted-imports
  ActionButton,
  IToggleProps,
} from "@fluentui/react";
import { useParams } from "react-router-dom";
import { produce } from "immer";
import { FormattedMessage, Context } from "@oursky/react-messageformat";
import {
  PortalAPIAppConfig,
  IdentityType,
  PrimaryAuthenticatorType,
  LoginIDKeyConfig,
  LoginIDKeyType,
  LoginIDEmailConfig,
  LoginIDUsernameConfig,
  PhoneInputConfig,
  VerificationConfig,
  AuthenticatorOOBSMSConfig,
  AuthenticatorPasswordConfig,
  AuthenticatorPhoneOTPMode,
  VerificationCriteria,
  VerificationClaimsConfig,
  ForgotPasswordConfig,
  PasswordPolicyFeatureConfig,
  authenticatorPhoneOTPModeList,
  verificationCriteriaList,
} from "../../types";
import {
  DEFAULT_TEMPLATE_LOCALE,
  RESOURCE_EMAIL_DOMAIN_BLOCKLIST,
  RESOURCE_EMAIL_DOMAIN_ALLOWLIST,
  RESOURCE_USERNAME_EXCLUDED_KEYWORDS_TXT,
} from "../../resources";
import {
  Resource,
  ResourceSpecifier,
  specifierId,
  expandSpecifier,
} from "../../util/resource";
import { clearEmptyObject } from "../../util/misc";
import ShowLoading from "../../ShowLoading";
import ShowError from "../../ShowError";
import ScreenContent from "../../ScreenContent";
import ScreenTitle from "../../ScreenTitle";
import Widget from "../../Widget";
import WidgetTitle from "../../WidgetTitle";
import WidgetSubtitle from "../../WidgetSubtitle";
import Link from "../../Link";
import {
  AppConfigFormModel,
  useAppConfigForm,
} from "../../hook/useAppConfigForm";
import FormContainer from "../../FormContainer";
import PriorityList from "../../PriorityList";
import WidgetDescription from "../../WidgetDescription";
import HorizontalDivider from "../../HorizontalDivider";
import FeatureDisabledMessageBar from "./FeatureDisabledMessageBar";
import CheckboxWithTooltip from "../../CheckboxWithTooltip";
import CheckboxWithContentLayout from "../../CheckboxWithContentLayout";
import CustomTagPicker from "../../CustomTagPicker";
import TextField from "../../TextField";
import Toggle from "../../Toggle";
import LabelWithTooltip from "../../LabelWithTooltip";
import PhoneInputListWidget from "./PhoneInputListWidget";
import PasswordSettings from "./PasswordSettings";
import ShowOnlyIfSIWEIsDisabled from "./ShowOnlyIfSIWEIsDisabled";
import { useTagPickerWithNewTags } from "../../hook/useInput";
import { fixTagPickerStyles } from "../../bugs";
import { useResourceForm } from "../../hook/useResourceForm";
import { useAppFeatureConfigQuery } from "./query/appFeatureConfigQuery";
import { makeValidationErrorMatchUnknownKindParseRule } from "../../error/parse";
import { parseIntegerAllowLeadingZeros } from "../../util/input";
import styles from "./LoginMethodConfigurationScreen.module.css";
import ChoiceButton from "../../ChoiceButton";

function splitByNewline(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function joinByNewline(list: string[]): string {
  return list.join("\n");
}

const PIVOT_STYLES = {
  itemContainer: {
    paddingTop: "24px",
  },
};

const DEFAULT_PHONE_OTP_MODE: AuthenticatorPhoneOTPMode = "whatsapp_sms";

const ERROR_RULES = [
  makeValidationErrorMatchUnknownKindParseRule(
    "const",
    /\/authentication\/identities/,
    "errors.validation.passkey"
  ),
];

const IDENTITY_TYPES: IdentityType[] = ["login_id"];
const PRIMARY_AUTHENTICATOR_TYPES: PrimaryAuthenticatorType[] = [
  "password",
  "oob_otp_email",
  "oob_otp_sms",
];
const LOGIN_ID_KEY_CONFIGS: LoginIDKeyConfig[] = [
  { type: "email" },
  { type: "phone" },
  { type: "username" },
];

// email domain lists are not language specific
// so the locale in ResourceSpecifier is not important
const emailDomainBlocklistSpecifier: ResourceSpecifier = {
  def: RESOURCE_EMAIL_DOMAIN_BLOCKLIST,
  locale: DEFAULT_TEMPLATE_LOCALE,
  extension: null,
};

const emailDomainAllowlistSpecifier: ResourceSpecifier = {
  def: RESOURCE_EMAIL_DOMAIN_ALLOWLIST,
  locale: DEFAULT_TEMPLATE_LOCALE,
  extension: null,
};

const usernameExcludeKeywordsTXTSpecifier: ResourceSpecifier = {
  def: RESOURCE_USERNAME_EXCLUDED_KEYWORDS_TXT,
  locale: DEFAULT_TEMPLATE_LOCALE,
  extension: null,
};

const specifiers: ResourceSpecifier[] = [
  emailDomainBlocklistSpecifier,
  emailDomainAllowlistSpecifier,
  usernameExcludeKeywordsTXTSpecifier,
];

interface ResourcesFormState {
  resources: Partial<Record<string, Resource>>;
}

function constructResourcesFormState(
  resources: Resource[]
): ResourcesFormState {
  const resourceMap: Partial<Record<string, Resource>> = {};
  for (const r of resources) {
    const id = specifierId(r.specifier);
    // Multiple resources may use same specifier ID (images),
    // use the first resource with non-empty values.
    if ((resourceMap[id]?.nullableValue ?? "") === "") {
      resourceMap[specifierId(r.specifier)] = r;
    }
  }

  return { resources: resourceMap };
}

function constructResources(state: ResourcesFormState): Resource[] {
  return Object.values(state.resources).filter(Boolean) as Resource[];
}

type LoginMethodPasswordlessLoginID = "email" | "phone" | "phone-email";
type LoginMethodPasswordLoginID =
  | "email"
  | "phone"
  | "phone-email"
  | "username";

type LoginMethodFirstLevelOption =
  | "email"
  | "phone"
  | "phone-email"
  | "username"
  | "oauth"
  | "custom";

type LoginMethodSecondLevelOption = "passwordless" | "password";

function loginMethodToFirstLevelOption(
  loginMethod: LoginMethod
): LoginMethodFirstLevelOption {
  if (loginMethod.startsWith("passwordless-")) {
    return loginMethod.slice(
      "passwordless-".length
    ) as LoginMethodFirstLevelOption;
  }
  if (loginMethod.startsWith("password-")) {
    return loginMethod.slice("password-".length) as LoginMethodFirstLevelOption;
  }
  return loginMethod as LoginMethodFirstLevelOption;
}

function loginMethodToSecondLevelOption(
  loginMethod: LoginMethod
): LoginMethodSecondLevelOption | null {
  if (loginMethod.startsWith("passwordless-")) {
    return "passwordless";
  }
  if (loginMethod.startsWith("password-")) {
    return "password";
  }
  return null;
}

type LoginMethod =
  | `passwordless-${LoginMethodPasswordlessLoginID}`
  | `password-${LoginMethodPasswordLoginID}`
  | "oauth"
  | "custom";

interface ControlOf<T> {
  isChecked: boolean;
  isDisabled: boolean;
  value: T;
}

// ControlList augments T with isChecked and isDisabled.
//
// controlListOf creates a list of ControlOf that this screen recognize.
//
// controlListPreserve turns a ControlList into plain list by preserving exotic values.
// This is useful for identities and primary_authenticators because
// "biometric", "anonymous", and "passkey" are exotic.
// They must be preserved.
//
// controlListUnwrap simply turns a ControlList into plain list.
//
// controlListIsEqualToPlainList determines whether a ControlList is equal to a plain list.
//
// controlListCheckWithPlainList checks a ControlList with a plain list.
type ControlList<T> = ControlOf<T>[];

function controlListOf<T>(
  eq: (a: T, b: T) => boolean,
  all: T[],
  current: T[]
): ControlList<T> {
  const out: ControlList<T> = [];

  for (const a of current) {
    const b = all.find((b) => eq(a, b));
    if (b != null) {
      out.push({
        isChecked: true,
        isDisabled: false,
        value: a,
      });
    }
  }

  for (const a of all) {
    const b = out.find((b) => eq(a, b.value));
    if (b == null) {
      out.push({
        isChecked: false,
        isDisabled: false,
        value: a,
      });
    }
  }
  return out;
}

function controlListIsEqualToPlainList<U, T>(
  eq: (u: U, t: T) => boolean,
  us: U[],
  ts: ControlList<T>
): boolean {
  const plains = ts.filter((t) => t.isChecked).map((t) => t.value);

  if (plains.length !== us.length) {
    return false;
  }

  for (let i = 0; i < us.length; i++) {
    const u = us[i];
    const t = plains[i];
    if (!eq(u, t)) {
      return false;
    }
  }

  return true;
}

function controlListPreserve<T>(
  eq: (a: T, b: T) => boolean,
  ts: ControlList<T>,
  plains: T[]
): T[] {
  const exotic = plains.filter((a) => {
    for (const t of ts) {
      if (eq(a, t.value)) {
        return false;
      }
    }
    return true;
  });

  return [...ts.filter((a) => a.isChecked).map((a) => a.value), ...exotic];
}

function controlListUnwrap<T>(ts: ControlList<T>): T[] {
  return ts.filter((a) => a.isChecked).map((a) => a.value);
}

function controlListCheckWithPlainList<U, T>(
  eq: (u: U, t: T) => boolean,
  us: U[],
  ts: ControlList<T>
): ControlList<T> {
  const checked: ControlList<T> = [];

  for (const u of us) {
    const t = ts.find((t) => eq(u, t.value));
    if (t != null) {
      checked.push({
        ...t,
        isChecked: true,
      });
    }
  }

  const unchecked: ControlList<T> = ts
    .filter((t) => {
      for (const u of us) {
        if (eq(u, t.value)) {
          return false;
        }
      }
      return true;
    })
    .map((t) => ({
      ...t,
      isChecked: false,
    }));

  const out: ControlList<T> = [...checked, ...unchecked];
  return out;
}

function controlListCheckWithPlainValue<U, T>(
  eq: (u: U, t: T) => boolean,
  u: U,
  isChecked: boolean,
  ts: ControlList<T>
): ControlList<T> {
  return ts.map((t) => {
    if (eq(u, t.value)) {
      return {
        ...t,
        isChecked,
      };
    }
    return t;
  });
}

function controlListSwap<T>(
  index1: number,
  index2: number,
  ts: ControlList<T>
): ControlList<T> {
  const newItems = [...ts];
  const thisItem = newItems[index1];
  const thatItem = newItems[index2];
  if (index1 < 0 || index2 < 0 || index1 >= ts.length || index2 >= ts.length) {
    return ts;
  }
  newItems[index1] = thatItem;
  newItems[index2] = thisItem;
  return newItems;
}

interface ConfigFormState {
  identitiesControl: ControlList<IdentityType>;
  primaryAuthenticatorsControl: ControlList<PrimaryAuthenticatorType>;
  loginIDKeyConfigsControl: ControlList<LoginIDKeyConfig>;
  loginIDEmailConfig: Required<LoginIDEmailConfig>;
  loginIDUsernameConfig: Required<LoginIDUsernameConfig>;
  phoneInputConfig: Required<PhoneInputConfig>;
  verificationConfig: VerificationConfig;
  authenticatorOOBSMSConfig: AuthenticatorOOBSMSConfig;
  authenticatorPasswordConfig: AuthenticatorPasswordConfig;
  forgotPasswordConfig: ForgotPasswordConfig;
  passkeyChecked: boolean;
}

interface FeatureConfigFormState {
  phoneLoginIDDisabled: boolean;
  passwordPolicyFeatureConfig: PasswordPolicyFeatureConfig;
}

interface FormState
  extends ConfigFormState,
    ResourcesFormState,
    FeatureConfigFormState {}

interface FormModel {
  isLoading: boolean;
  isUpdating: boolean;
  isDirty: boolean;
  loadError: unknown;
  updateError: unknown;
  state: FormState;
  setState: (fn: (state: FormState) => FormState) => void;
  reload: () => void;
  reset: () => void;
  save: () => Promise<void>;
}

// eslint-disable-next-line complexity
function loginMethodFromFormState(formState: FormState): LoginMethod {
  const {
    identitiesControl,
    loginIDKeyConfigsControl,
    primaryAuthenticatorsControl,
  } = formState;

  if (
    loginIDIdentity(identitiesControl) &&
    loginIDOf(["email"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["oob_otp_email"], primaryAuthenticatorsControl)
  ) {
    return "passwordless-email";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    loginIDOf(["phone"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["oob_otp_sms"], primaryAuthenticatorsControl)
  ) {
    return "passwordless-phone";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    // Order is important.
    loginIDOf(["phone", "email"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(
      ["oob_otp_sms", "oob_otp_email"],
      primaryAuthenticatorsControl
    )
  ) {
    return "passwordless-phone-email";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    loginIDOf(["email"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["password"], primaryAuthenticatorsControl)
  ) {
    return "password-email";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    loginIDOf(["phone"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["password"], primaryAuthenticatorsControl)
  ) {
    return "password-phone";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    // Order is important.
    loginIDOf(["phone", "email"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["password"], primaryAuthenticatorsControl)
  ) {
    return "password-phone-email";
  }

  if (
    loginIDIdentity(identitiesControl) &&
    loginIDOf(["username"], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf(["password"], primaryAuthenticatorsControl)
  ) {
    return "password-username";
  }

  if (
    oauthIdentity(identitiesControl) &&
    loginIDOf([], loginIDKeyConfigsControl) &&
    primaryAuthenticatorOf([], primaryAuthenticatorsControl)
  ) {
    return "oauth";
  }

  return "custom";
}

function setLoginMethodToFormState(
  formState: FormState,
  loginMethod: LoginMethod
) {
  switch (loginMethod) {
    case "passwordless-email":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["email"]);
      setPrimaryAuthenticator(formState, ["oob_otp_email"]);
      break;
    case "passwordless-phone":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["phone"]);
      setPrimaryAuthenticator(formState, ["oob_otp_sms"]);
      break;
    case "passwordless-phone-email":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["phone", "email"]);
      setPrimaryAuthenticator(formState, ["oob_otp_sms", "oob_otp_email"]);
      break;
    case "password-email":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["email"]);
      setPrimaryAuthenticator(formState, ["password"]);
      break;
    case "password-phone":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["phone"]);
      setPrimaryAuthenticator(formState, ["password"]);
      break;
    case "password-phone-email":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["phone", "email"]);
      setPrimaryAuthenticator(formState, ["password"]);
      break;
    case "password-username":
      setLoginIDIdentity(formState);
      setLoginID(formState, ["username"]);
      setPrimaryAuthenticator(formState, ["password"]);
      break;
    case "oauth":
      setOAuthIdentity(formState);
      setLoginID(formState, []);
      setPrimaryAuthenticator(formState, []);
      break;
    case "custom":
      // No changes.
      break;
  }
}

// eslint-disable-next-line complexity
function correctInitialFormState(state: ConfigFormState): void {
  // Uncheck "login_id" identity if no login ID is checked.
  const allLoginIDUnchecked = state.loginIDKeyConfigsControl.every(
    (a) => !a.isChecked
  );
  if (allLoginIDUnchecked) {
    for (const t of state.identitiesControl) {
      if (t.value === "login_id") {
        t.isChecked = false;
      }
    }
  }

  // Disable "oob_otp_sms" or "oob_otp_email" if the corresponding login ID is unchecked.
  // Note that we do NOT uncheck.
  for (const loginID of state.loginIDKeyConfigsControl) {
    for (const authenticator of state.primaryAuthenticatorsControl) {
      if (
        loginID.value.type === "email" &&
        authenticator.value === "oob_otp_email"
      ) {
        authenticator.isDisabled = !loginID.isChecked;
      }
      if (
        loginID.value.type === "phone" &&
        authenticator.value === "oob_otp_sms"
      ) {
        authenticator.isDisabled = !loginID.isChecked;
      }
    }
  }
}

// eslint-disable-next-line complexity
function correctCurrentFormState(state: FormState): void {
  // Check or uncheck "login_id" identity.
  const allLoginIDUnchecked = state.loginIDKeyConfigsControl.every(
    (a) => !a.isChecked
  );
  const someLoginIDChecked = !allLoginIDUnchecked;
  for (const t of state.identitiesControl) {
    if (t.value === "login_id") {
      t.isChecked = someLoginIDChecked;
    }
  }

  // Disable and unchecked "oob_otp_sms" or "oob_otp_email" if the corresponding login ID is unchecked.
  for (const loginID of state.loginIDKeyConfigsControl) {
    for (const authenticator of state.primaryAuthenticatorsControl) {
      if (
        loginID.value.type === "email" &&
        authenticator.value === "oob_otp_email"
      ) {
        authenticator.isDisabled = !loginID.isChecked;
        if (authenticator.isDisabled && authenticator.isChecked) {
          authenticator.isChecked = false;
        }
      }
      if (
        loginID.value.type === "phone" &&
        authenticator.value === "oob_otp_sms"
      ) {
        authenticator.isDisabled = !loginID.isChecked;
        if (authenticator.isDisabled && authenticator.isChecked) {
          authenticator.isChecked = false;
        }
      }
    }
  }
}

function loginIDIdentity(identities: ControlList<IdentityType>): boolean {
  return controlListIsEqualToPlainList(
    (a, b) => a === b,
    ["login_id"] as IdentityType[],
    identities
  );
}

function oauthIdentity(identities: ControlList<IdentityType>): boolean {
  return controlListIsEqualToPlainList(
    (a, b) => a === b,
    [] as IdentityType[],
    identities
  );
}

function loginIDOf(
  types: LoginIDKeyType[],
  loginIDKeyConfigs: ControlList<LoginIDKeyConfig>
): boolean {
  return controlListIsEqualToPlainList(
    (u, t) => {
      return u === t.type;
    },
    types,
    loginIDKeyConfigs
  );
}

function primaryAuthenticatorOf(
  types: PrimaryAuthenticatorType[],
  primaryAuthenticators: ControlList<PrimaryAuthenticatorType>
): boolean {
  return controlListIsEqualToPlainList(
    (u, t) => {
      return u === t;
    },
    types,
    primaryAuthenticators
  );
}

function setLoginIDIdentity(draft: FormState) {
  draft.identitiesControl = controlListCheckWithPlainList(
    (a, b) => a === b,
    ["login_id"] as IdentityType[],
    draft.identitiesControl
  );
}

function setOAuthIdentity(draft: FormState) {
  draft.identitiesControl = controlListCheckWithPlainList(
    (a, b) => a === b,
    [] as IdentityType[],
    draft.identitiesControl
  );
}

function setLoginID(draft: FormState, types: LoginIDKeyType[]) {
  draft.loginIDKeyConfigsControl = controlListCheckWithPlainList(
    (a, b) => a === b.type,
    types,
    draft.loginIDKeyConfigsControl
  );
}

function setPrimaryAuthenticator(
  draft: FormState,
  types: PrimaryAuthenticatorType[]
) {
  draft.primaryAuthenticatorsControl = controlListCheckWithPlainList(
    (a, b) => a === b,
    types,
    draft.primaryAuthenticatorsControl
  );
}

function constructFormState(config: PortalAPIAppConfig): ConfigFormState {
  const identities = config.authentication?.identities ?? [];
  const primaryAuthenticators =
    config.authentication?.primary_authenticators ?? [];
  const loginIDKeyConfigs = config.identity?.login_id?.keys ?? [];

  const passkeyIndex =
    config.authentication?.primary_authenticators?.indexOf("passkey");

  const state = {
    identitiesControl: controlListOf(
      (a, b) => a === b,
      IDENTITY_TYPES,
      identities
    ),
    primaryAuthenticatorsControl: controlListOf(
      (a, b) => a === b,
      PRIMARY_AUTHENTICATOR_TYPES,
      primaryAuthenticators
    ),
    loginIDKeyConfigsControl: controlListOf(
      (a, b) => a.type === b.type,
      LOGIN_ID_KEY_CONFIGS,
      loginIDKeyConfigs
    ),
    loginIDEmailConfig: {
      block_plus_sign: false,
      case_sensitive: false,
      ignore_dot_sign: false,
      domain_blocklist_enabled: false,
      domain_allowlist_enabled: false,
      block_free_email_provider_domains: false,
      ...config.identity?.login_id?.types?.email,
    },
    loginIDUsernameConfig: {
      block_reserved_usernames: true,
      exclude_keywords_enabled: false,
      ascii_only: true,
      case_sensitive: false,
      ...config.identity?.login_id?.types?.username,
    },
    phoneInputConfig: {
      allowlist: [],
      pinned_list: [],
      preselect_by_ip_disabled: false,
      ...config.ui?.phone_input,
    },
    verificationConfig: {
      ...config.verification,
    },
    authenticatorOOBSMSConfig: {
      phone_otp_mode: DEFAULT_PHONE_OTP_MODE,
      ...config.authenticator?.oob_otp?.sms,
    },
    authenticatorPasswordConfig: {
      ...config.authenticator?.password,
      policy: {
        min_length: 8,
        uppercase_required: false,
        lowercase_required: false,
        digit_required: false,
        symbol_required: false,
        minimum_guessable_level: 0 as const,
        excluded_keywords: [],
        history_size: 0,
        history_days: 0,
        ...config.authenticator?.password?.policy,
      },
    },
    forgotPasswordConfig: {
      ...config.forgot_password,
    },
    passkeyChecked: passkeyIndex != null && passkeyIndex >= 0,
  };
  correctInitialFormState(state);
  return state;
}

function setEnable<T extends string>(
  arr: T[],
  value: T,
  enabled: boolean
): T[] {
  const index = arr.indexOf(value);

  if (enabled) {
    if (index >= 0) {
      return arr;
    }
    return [...arr, value];
  }

  if (index < 0) {
    return arr;
  }
  return [...arr.slice(0, index), ...arr.slice(index + 1)];
}

function constructConfig(
  config: PortalAPIAppConfig,
  _initialState: ConfigFormState,
  currentState: ConfigFormState,
  effectiveConfig: PortalAPIAppConfig
): PortalAPIAppConfig {
  // eslint-disable-next-line complexity
  return produce(config, (config) => {
    config.authentication ??= {};
    config.identity ??= {};
    config.identity.login_id ??= {};
    config.identity.login_id.types ??= {};
    config.ui ??= {};
    config.authenticator ??= {};
    config.authenticator.oob_otp ??= {};

    config.authentication.identities = controlListPreserve(
      (a, b) => a === b,
      currentState.identitiesControl,
      effectiveConfig.authentication?.identities ?? []
    );
    config.authentication.primary_authenticators = controlListPreserve(
      (a, b) => a === b,
      currentState.primaryAuthenticatorsControl,
      effectiveConfig.authentication?.primary_authenticators ?? []
    );
    if (currentState.passkeyChecked) {
      config.authentication.primary_authenticators = setEnable(
        config.authentication.primary_authenticators,
        "passkey",
        true
      );
      config.authentication.identities = setEnable(
        config.authentication.identities,
        "passkey",
        true
      );
    } else {
      config.authentication.primary_authenticators = setEnable(
        config.authentication.primary_authenticators,
        "passkey",
        false
      );
      config.authentication.identities = setEnable(
        config.authentication.identities,
        "passkey",
        false
      );
    }

    config.identity.login_id.keys = controlListUnwrap(
      currentState.loginIDKeyConfigsControl
    );
    config.identity.login_id.types.email = currentState.loginIDEmailConfig;
    config.ui.phone_input = currentState.phoneInputConfig;
    config.identity.login_id.types.username =
      currentState.loginIDUsernameConfig;
    config.verification = currentState.verificationConfig;
    config.authenticator.oob_otp.sms = currentState.authenticatorOOBSMSConfig;
    config.authenticator.password = currentState.authenticatorPasswordConfig;
    config.forgot_password = currentState.forgotPasswordConfig;

    clearEmptyObject(config);
  });
}

interface WidgetSubsectionProps {
  children?: ReactNode;
}

function WidgetSubsection(props: WidgetSubsectionProps) {
  const { children } = props;
  return <div className={styles.widgetSubsection}>{children}</div>;
}

const LOGIN_METHOD_ICON: Record<LoginMethodFirstLevelOption, string> = {
  email: "mail",
  phone: "device-tablet",
  "phone-email": "mixed",
  username: "user",
  oauth: "atom",
  custom: "puzzle",
};

interface LoginMethodIconProps {
  className?: string;
  size: "60px" | "48px";
  variant: LoginMethodFirstLevelOption;
  checked?: boolean;
}

function LoginMethodIcon(props: LoginMethodIconProps) {
  const { className, size, variant, checked } = props;
  const theme = useTheme();
  const iconName = LOGIN_METHOD_ICON[variant];

  const backgroundColor = checked
    ? theme.palette.themePrimary
    : theme.palette.neutralLight;
  const color = checked ? theme.palette.white : theme.palette.neutralTertiary;

  if (iconName === "mixed") {
    return (
      <div
        className={cn(className, styles.loginMethodIcon)}
        style={{
          backgroundColor,
          width: size,
          height: size,
        }}
      >
        <i
          className={cn(styles.loginMethodIconIcon, "ti", "ti-device-tablet")}
          style={{
            color,
            marginTop: "-8px",
            marginRight: "-4px",
          }}
        ></i>
        <i
          className={cn(styles.loginMethodIconIcon, "ti", "ti-mail")}
          style={{
            color,
            marginBottom: "-8px",
            marginLeft: "-4px",
          }}
        ></i>
      </div>
    );
  }

  return (
    <div
      className={cn(className, styles.loginMethodIcon)}
      style={{
        backgroundColor,
        width: size,
        height: size,
      }}
    >
      <i
        className={cn(styles.loginMethodIconIcon, "ti", `ti-${iconName}`)}
        style={{
          color,
        }}
      ></i>
    </div>
  );
}

interface ChosenLoginMethodProps {
  loginMethod: LoginMethod;
  passkeyChecked: boolean;
}

function ChosenLoginMethod(props: ChosenLoginMethodProps) {
  const { loginMethod, passkeyChecked } = props;
  const variant = useMemo(() => {
    return loginMethodToFirstLevelOption(loginMethod);
  }, [loginMethod]);
  return (
    <div className={styles.widget}>
      <div className={styles.chosenLoginMethodRoot}>
        <LoginMethodIcon size="48px" variant={variant} checked={true} />
        <div
          className={
            passkeyChecked
              ? styles.chosenLoginMethodTitleDescription
              : styles.chosenLoginMethodTitleOnly
          }
        >
          <Text
            variant="large"
            block={true}
            className={styles.chosenLoginMethodTitle}
          >
            <FormattedMessage
              id={
                "LoginMethodConfigurationScreen.login-method.title." +
                loginMethod
              }
            />
          </Text>
          {passkeyChecked ? (
            <Text variant="medium" block={true}>
              <FormattedMessage id="LoginMethodConfigurationScreen.with-passkey" />
            </Text>
          ) : null}
        </div>
      </div>
    </div>
  );
}

interface LoginMethodButtonProps {
  targetValue: LoginMethodFirstLevelOption;
  currentValue: LoginMethodFirstLevelOption;
  disabled?: boolean;
  onClick?: (firstLevelOption: LoginMethodFirstLevelOption) => void;
}

function LoginMethodButton(props: LoginMethodButtonProps) {
  const { targetValue, currentValue, disabled, onClick: onClickProp } = props;
  const checked = targetValue === currentValue;

  const onRenderIcon = useCallback(() => {
    return (
      <LoginMethodIcon variant={targetValue} size="60px" checked={checked} />
    );
  }, [targetValue, checked]);

  const onClick = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      onClickProp?.(targetValue);
    },
    [onClickProp, targetValue]
  );

  return (
    <ActionButton
      disabled={disabled}
      checked={checked}
      styles={{
        root: {
          height: "auto",
          opacity: disabled === true ? "0.5" : undefined,
        },
        flexContainer: {
          flexDirection: "column",
          rowGap: "4px",
        },
      }}
      onRenderIcon={onRenderIcon}
      onClick={onClick}
      toggle={true}
    >
      <Text
        block={true}
        styles={{
          root: {
            fontWeight: "600",
          },
        }}
      >
        <FormattedMessage
          id={`LoginMethodConfigurationScreen.first-level.${targetValue}.title`}
        />
      </Text>
      <Text block={true}>
        <FormattedMessage
          id={`LoginMethodConfigurationScreen.first-level.${targetValue}.description`}
        />
      </Text>
    </ActionButton>
  );
}

const AUTHENTICATION_BUTTON_ICON: Record<LoginMethodSecondLevelOption, string> =
  {
    passwordless: "mailbox",
    password: "forms",
  };

interface AuthenticationButtonProps {
  targetValue: LoginMethodSecondLevelOption;
  currentValue: LoginMethodSecondLevelOption;
  disabled?: boolean;
  onClick?: (secondLevelOption: LoginMethodSecondLevelOption) => void;
}

function AuthenticationButton(props: AuthenticationButtonProps) {
  const { targetValue, currentValue, disabled, onClick: onClickProp } = props;
  const checked = targetValue === currentValue;
  const iconName = AUTHENTICATION_BUTTON_ICON[targetValue];

  const IconComponent = useCallback(
    (props) => {
      return (
        <i
          className={cn(
            styles.authenticationButtonIcon,
            "ti",
            `ti-${iconName}`
          )}
          style={{
            color: disabled === true ? props.disabledColor : undefined,
          }}
        ></i>
      );
    },
    [disabled, iconName]
  );

  const onClick = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      onClickProp?.(targetValue);
    },
    [onClickProp, targetValue]
  );

  const buttonStyles = useMemo(() => {
    return {
      flexContainer: {
        columnGap: "16px",
      },
    };
  }, []);

  return (
    <ChoiceButton
      className={styles.authenticationButton}
      styles={buttonStyles}
      disabled={disabled}
      checked={checked}
      text={
        <FormattedMessage
          id={`LoginMethodConfigurationScreen.second-level.${targetValue}.title`}
        />
      }
      secondaryText={
        <FormattedMessage
          id={`LoginMethodConfigurationScreen.second-level.${targetValue}.description`}
        />
      }
      IconComponent={IconComponent}
      onClick={onClick}
    />
  );
}

interface LoginMethodChooserProps {
  loginMethod: LoginMethod;
  phoneLoginIDDisabled: boolean;
  passkeyChecked: boolean;
  appID: string;
  onChangeLoginMethod: (loginMethod: LoginMethod) => void;
  onChangePasskeyChecked?: IToggleProps["onChange"];
}

function LoginMethodChooser(props: LoginMethodChooserProps) {
  const {
    loginMethod,
    phoneLoginIDDisabled,
    appID,
    onChangeLoginMethod,
    passkeyChecked,
    onChangePasskeyChecked,
  } = props;
  const disabled = phoneLoginIDDisabled;

  const firstLevelOption = useMemo(
    () => loginMethodToFirstLevelOption(loginMethod),
    [loginMethod]
  );
  const secondLevelOption = useMemo(
    () => loginMethodToSecondLevelOption(loginMethod),
    [loginMethod]
  );

  const onChangeFirstLevelOption = useCallback(
    (firstLevelOption: LoginMethodFirstLevelOption) => {
      if (firstLevelOption === "oauth" || firstLevelOption === "custom") {
        onChangeLoginMethod(firstLevelOption);
      } else {
        // Reset to password.
        onChangeLoginMethod(`password-${firstLevelOption}` as LoginMethod);
      }
    },
    [onChangeLoginMethod]
  );

  const onChangeSecondLevelOption = useCallback(
    (secondLevelOption: LoginMethodSecondLevelOption) => {
      if (
        firstLevelOption !== "oauth" &&
        firstLevelOption !== "custom" &&
        firstLevelOption !== "username"
      ) {
        onChangeLoginMethod(`${secondLevelOption}-${firstLevelOption}`);
      }
    },
    [firstLevelOption, onChangeLoginMethod]
  );

  const firstLevel = [
    <LoginMethodButton
      key="email"
      targetValue="email"
      currentValue={firstLevelOption}
      onClick={onChangeFirstLevelOption}
    />,
  ];
  if (!disabled) {
    firstLevel.push(
      <LoginMethodButton
        key="phone"
        targetValue="phone"
        currentValue={firstLevelOption}
        disabled={disabled}
        onClick={onChangeFirstLevelOption}
      />
    );
    firstLevel.push(
      <LoginMethodButton
        key="phone-email"
        targetValue="phone-email"
        currentValue={firstLevelOption}
        disabled={disabled}
        onClick={onChangeFirstLevelOption}
      />
    );
  }
  firstLevel.push(
    <LoginMethodButton
      key="username"
      targetValue="username"
      currentValue={firstLevelOption}
      onClick={onChangeFirstLevelOption}
    />
  );
  firstLevel.push(
    <LoginMethodButton
      key="oauth"
      targetValue="oauth"
      currentValue={firstLevelOption}
      onClick={onChangeFirstLevelOption}
    />
  );
  firstLevel.push(
    <LoginMethodButton
      key="custom"
      targetValue="custom"
      currentValue={firstLevelOption}
      onClick={onChangeFirstLevelOption}
    />
  );
  if (disabled) {
    firstLevel.push(
      <LoginMethodButton
        key="phone"
        targetValue="phone"
        currentValue={firstLevelOption}
        disabled={disabled}
        onClick={onChangeFirstLevelOption}
      />
    );
    firstLevel.push(
      <LoginMethodButton
        key="phone-email"
        targetValue="phone-email"
        currentValue={firstLevelOption}
        disabled={disabled}
        onClick={onChangeFirstLevelOption}
      />
    );
  }

  return (
    <Widget className={styles.widget}>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.chooser.title" />
      </WidgetTitle>
      {phoneLoginIDDisabled ? (
        <FeatureDisabledMessageBar messageID="FeatureConfig.disabled" />
      ) : null}
      <div className={styles.chooserGrid}>{firstLevel}</div>
      {secondLevelOption != null ? (
        <>
          <WidgetSubtitle>
            <FormattedMessage id="LoginMethodConfigurationScreen.chooser.subtitle" />
          </WidgetSubtitle>
          <div className={styles.chooserFlex}>
            <AuthenticationButton
              targetValue="passwordless"
              currentValue={secondLevelOption}
              disabled={
                !["email", "phone", "phone-email"].includes(firstLevelOption)
              }
              onClick={onChangeSecondLevelOption}
            />
            <AuthenticationButton
              targetValue="password"
              currentValue={secondLevelOption}
              onClick={onChangeSecondLevelOption}
            />
          </div>
        </>
      ) : null}
      {loginMethod === "oauth" ? (
        <LinkToOAuth appID={appID} />
      ) : (
        <Toggle
          inlineLabel={true}
          label={
            <FormattedMessage id="LoginMethodConfigurationScreen.passkey.title" />
          }
          checked={passkeyChecked}
          onChange={onChangePasskeyChecked}
        />
      )}
    </Widget>
  );
}

interface LinkToOAuthProps {
  appID: string;
}

function LinkToOAuth(props: LinkToOAuthProps) {
  const { appID } = props;

  return (
    <Link
      className={styles.oauthLink}
      to={`/project/${appID}/configuration/authentication/external-oauth`}
    >
      <FormattedMessage id="LoginMethodConfigurationScreen.oauth" />
    </Link>
  );
}

interface CustomLoginMethodsProps {
  phoneLoginIDDisabled: boolean;
  primaryAuthenticatorsControl: ControlList<PrimaryAuthenticatorType>;
  loginIDKeyConfigsControl: ControlList<LoginIDKeyConfig>;
  onChangeLoginIDChecked: (key: LoginIDKeyType, checked: boolean) => void;
  onSwapLoginID: (index1: number, index2: number) => void;
  onChangePrimaryAuthenticatorChecked: (
    key: PrimaryAuthenticatorType,
    checked: boolean
  ) => void;
  onSwapPrimaryAuthenticator: (index1: number, index2: number) => void;
}

function CustomLoginMethods(props: CustomLoginMethodsProps) {
  const {
    phoneLoginIDDisabled,
    loginIDKeyConfigsControl,
    primaryAuthenticatorsControl,
    onChangeLoginIDChecked: onChangeLoginIDCheckedProp,
    onSwapLoginID: onSwapLoginIDProp,
    onChangePrimaryAuthenticatorChecked:
      onChangePrimaryAuthenticatorCheckedProp,
    onSwapPrimaryAuthenticator: onSwapPrimaryAuthenticatorProp,
  } = props;

  const { renderToString } = useContext(Context);

  const {
    semanticColors: { disabledText },
  } = useTheme();

  const loginIDs = useMemo(() => {
    return loginIDKeyConfigsControl.map((a) => {
      let disabled = a.isDisabled;
      if (a.value.type === "phone") {
        disabled = disabled || phoneLoginIDDisabled;
      }
      return {
        key: a.value.type,
        checked: a.isChecked,
        disabled,
        content: (
          <Text
            variant="small"
            block={true}
            styles={{
              root: {
                color: disabled ? disabledText : undefined,
              },
            }}
          >
            <FormattedMessage id={"LoginIDKeyType." + a.value.type} />
          </Text>
        ),
      };
    });
  }, [loginIDKeyConfigsControl, phoneLoginIDDisabled, disabledText]);

  const onChangeLoginIDChecked = useCallback(
    (key: string, checked: boolean) => {
      onChangeLoginIDCheckedProp(key as LoginIDKeyType, checked);
    },
    [onChangeLoginIDCheckedProp]
  );

  const onSwapLoginID = useCallback(
    (index1: number, index2: number) => {
      onSwapLoginIDProp(index1, index2);
    },
    [onSwapLoginIDProp]
  );

  const authenticators = useMemo(() => {
    return primaryAuthenticatorsControl.map((a) => {
      let disabled = a.isDisabled;
      if (a.value === "oob_otp_sms") {
        disabled = disabled || phoneLoginIDDisabled;
      }
      return {
        key: a.value,
        checked: a.isChecked,
        disabled,
        content: (
          <Text
            variant="small"
            block={true}
            styles={{
              root: {
                color: disabled ? disabledText : undefined,
              },
            }}
          >
            <FormattedMessage id={"PrimaryAuthenticatorType." + a.value} />
          </Text>
        ),
      };
    });
  }, [primaryAuthenticatorsControl, phoneLoginIDDisabled, disabledText]);

  const onChangePrimaryAuthenticatorChecked = useCallback(
    (key: string, checked: boolean) => {
      onChangePrimaryAuthenticatorCheckedProp(
        key as PrimaryAuthenticatorType,
        checked
      );
    },
    [onChangePrimaryAuthenticatorCheckedProp]
  );

  const onSwapPrimaryAuthenticator = useCallback(
    (index1: number, index2: number) => {
      onSwapPrimaryAuthenticatorProp(index1, index2);
    },
    [onSwapPrimaryAuthenticatorProp]
  );

  return (
    <Widget>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.custom-login-methods.title" />
      </WidgetTitle>
      {phoneLoginIDDisabled ? (
        <FeatureDisabledMessageBar messageID="FeatureConfig.disabled" />
      ) : null}
      <WidgetSubsection>
        <WidgetSubtitle>
          <FormattedMessage id="LoginMethodConfigurationScreen.custom-login-methods.login-id.title" />
        </WidgetSubtitle>
        <WidgetDescription>
          <FormattedMessage id="LoginMethodConfigurationScreen.custom-login-methods.login-id.description" />
        </WidgetDescription>
      </WidgetSubsection>
      <PriorityList
        items={loginIDs}
        checkedColumnLabel={renderToString("activate")}
        keyColumnLabel={renderToString(
          "LoginMethodConfigurationScreen.custom-login-methods.login-id.title"
        )}
        onChangeChecked={onChangeLoginIDChecked}
        onSwap={onSwapLoginID}
      />
      <HorizontalDivider />
      <WidgetSubsection>
        <WidgetSubtitle>
          <FormattedMessage id="LoginMethodConfigurationScreen.custom-login-methods.authenticator.title" />
        </WidgetSubtitle>
        <WidgetDescription>
          <FormattedMessage id="LoginMethodConfigurationScreen.custom-login-methods.authenticator.description" />
        </WidgetDescription>
      </WidgetSubsection>
      <PriorityList
        items={authenticators}
        checkedColumnLabel={renderToString("activate")}
        keyColumnLabel={renderToString(
          "LoginMethodConfigurationScreen.custom-login-methods.authenticator.title"
        )}
        onChangeChecked={onChangePrimaryAuthenticatorChecked}
        onSwap={onSwapPrimaryAuthenticator}
      />
    </Widget>
  );
}

function useEmailConfigCheckboxOnChange(
  setState: AppConfigFormModel<FormState>["setState"],
  key: keyof LoginIDEmailConfig
): ICheckboxProps["onChange"] {
  const onChange = useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.loginIDEmailConfig[key] = checked;
        })
      );
    },
    [key, setState]
  );
  return onChange;
}

function useLinesValue(
  resources: Partial<Record<string, Resource>>,
  specifier: ResourceSpecifier
) {
  return useMemo(() => {
    const value = resources[specifierId(specifier)]?.nullableValue;
    if (value == null) {
      return [];
    }
    return splitByNewline(value);
  }, [resources, specifier]);
}

function useUpdateLinesValue(
  setState: FormModel["setState"],
  specifier: ResourceSpecifier
) {
  return useCallback(
    (value: string[]) => {
      setState((prev) => {
        const updatedResources = { ...prev.resources };
        const newResource: Resource = {
          specifier,
          path: expandSpecifier(specifier),
          nullableValue: joinByNewline(value),
        };
        updatedResources[specifierId(newResource.specifier)] = newResource;
        return {
          ...prev,
          resources: updatedResources,
        };
      });
    },
    [setState, specifier]
  );
}

function useOnChangeModifyDisabled(
  setState: FormModel["setState"],
  typ: LoginIDKeyType
) {
  return useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          const c = prev.loginIDKeyConfigsControl.find(
            (a) => a.value.type === typ
          );
          if (c != null) {
            c.value.modify_disabled = checked;
          }
        })
      );
    },
    [setState, typ]
  );
}

interface EmailSettingsProps {
  resources: Partial<Record<string, Resource>>;
  loginIDKeyConfigsControl: ControlList<LoginIDKeyConfig>;
  loginIDEmailConfig: Required<LoginIDEmailConfig>;
  setState: AppConfigFormModel<FormState>["setState"];
}

function EmailSettings(props: EmailSettingsProps) {
  const { resources, loginIDEmailConfig, loginIDKeyConfigsControl, setState } =
    props;
  const { renderToString } = useContext(Context);

  const onChangeCaseSensitive = useEmailConfigCheckboxOnChange(
    setState,
    "case_sensitive"
  );
  const onChangeIgnoreDotSign = useEmailConfigCheckboxOnChange(
    setState,
    "ignore_dot_sign"
  );
  const onChangeBlockPlusSign = useEmailConfigCheckboxOnChange(
    setState,
    "block_plus_sign"
  );

  const onChangeBlocklistEnabled = useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.loginIDEmailConfig.domain_blocklist_enabled = checked;
          if (prev.loginIDEmailConfig.domain_blocklist_enabled) {
            prev.loginIDEmailConfig.domain_allowlist_enabled = false;
          } else {
            prev.loginIDEmailConfig.block_free_email_provider_domains = false;
          }
        })
      );
    },
    [setState]
  );
  const {
    selectedItems: blocklist,
    onChange: onChangeBlocklist,
    onResolveSuggestions: onResolveSuggestionsBlocklist,
    onAdd: onAddBlocklist,
  } = useTagPickerWithNewTags(
    useLinesValue(resources, emailDomainBlocklistSpecifier),
    useUpdateLinesValue(setState, emailDomainBlocklistSpecifier)
  );

  const onChangeAllowlistEnabled = useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.loginIDEmailConfig.domain_allowlist_enabled = checked;
          if (prev.loginIDEmailConfig.domain_allowlist_enabled) {
            prev.loginIDEmailConfig.domain_blocklist_enabled = false;
            prev.loginIDEmailConfig.block_free_email_provider_domains = false;
          }
        })
      );
    },
    [setState]
  );
  const {
    selectedItems: allowlist,
    onChange: onChangeAllowlist,
    onResolveSuggestions: onResolveSuggestionsAllowlist,
    onAdd: onAddAllowlist,
  } = useTagPickerWithNewTags(
    useLinesValue(resources, emailDomainAllowlistSpecifier),
    useUpdateLinesValue(setState, emailDomainAllowlistSpecifier)
  );

  const onChangeBlockFreeEmailProviderDomains = useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.loginIDEmailConfig.block_free_email_provider_domains = checked;
          if (prev.loginIDEmailConfig.block_free_email_provider_domains) {
            prev.loginIDEmailConfig.domain_allowlist_enabled = false;
            prev.loginIDEmailConfig.domain_blocklist_enabled = true;
          }
        })
      );
    },
    [setState]
  );

  const onChangeModifyDisabled = useOnChangeModifyDisabled(setState, "email");

  return (
    <Widget>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.email.title" />
      </WidgetTitle>
      <WidgetDescription>
        <FormattedMessage id="LoginMethodConfigurationScreen.email.description" />
      </WidgetDescription>
      <Checkbox
        label={renderToString("LoginIDConfigurationScreen.email.caseSensitive")}
        checked={loginIDEmailConfig.case_sensitive}
        onChange={onChangeCaseSensitive}
      />
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.email.ignoreDotLocal"
        )}
        checked={loginIDEmailConfig.ignore_dot_sign}
        onChange={onChangeIgnoreDotSign}
      />
      <CheckboxWithTooltip
        label={renderToString("LoginIDConfigurationScreen.email.blockPlus")}
        checked={loginIDEmailConfig.block_plus_sign}
        tooltipMessageId="LoginIDConfigurationScreen.email.blockPlusTooltipMessage"
        onChange={onChangeBlockPlusSign}
      />
      <CheckboxWithContentLayout>
        <CheckboxWithTooltip
          label={renderToString(
            "LoginIDConfigurationScreen.email.domainBlocklist"
          )}
          checked={loginIDEmailConfig.domain_blocklist_enabled}
          onChange={onChangeBlocklistEnabled}
          disabled={loginIDEmailConfig.domain_allowlist_enabled}
          tooltipMessageId="LoginIDConfigurationScreen.email.domainBlocklistTooltipMessage"
        />
        <CustomTagPicker
          styles={fixTagPickerStyles}
          inputProps={{
            "aria-label": renderToString(
              "LoginIDConfigurationScreen.email.domainBlocklist"
            ),
          }}
          disabled={!loginIDEmailConfig.domain_blocklist_enabled}
          selectedItems={blocklist}
          onChange={onChangeBlocklist}
          onResolveSuggestions={onResolveSuggestionsBlocklist}
          onAdd={onAddBlocklist}
        />
      </CheckboxWithContentLayout>
      <CheckboxWithTooltip
        label={renderToString(
          "LoginIDConfigurationScreen.email.blockFreeEmailProviderDomains"
        )}
        checked={loginIDEmailConfig.block_free_email_provider_domains}
        disabled={loginIDEmailConfig.domain_allowlist_enabled}
        tooltipMessageId="LoginIDConfigurationScreen.email.blockFreeEmailProviderDomainsTooltipMessage"
        onChange={onChangeBlockFreeEmailProviderDomains}
      />
      <CheckboxWithContentLayout>
        <CheckboxWithTooltip
          label={renderToString(
            "LoginIDConfigurationScreen.email.domainAllowlist"
          )}
          checked={loginIDEmailConfig.domain_allowlist_enabled}
          onChange={onChangeAllowlistEnabled}
          disabled={loginIDEmailConfig.domain_blocklist_enabled}
          tooltipMessageId="LoginIDConfigurationScreen.email.domainAllowlistTooltipMessage"
        />
        <CustomTagPicker
          styles={fixTagPickerStyles}
          inputProps={{
            "aria-label": renderToString(
              "LoginIDConfigurationScreen.email.domainAllowlist"
            ),
          }}
          disabled={!loginIDEmailConfig.domain_allowlist_enabled}
          selectedItems={allowlist}
          onChange={onChangeAllowlist}
          onResolveSuggestions={onResolveSuggestionsAllowlist}
          onAdd={onAddAllowlist}
        />
      </CheckboxWithContentLayout>
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.email.modify-disabled"
        )}
        checked={
          loginIDKeyConfigsControl.find((a) => a.value.type === "email")?.value
            .modify_disabled ?? false
        }
        onChange={onChangeModifyDisabled}
      />
    </Widget>
  );
}

interface PhoneSettingsProps {
  loginIDKeyConfigsControl: ControlList<LoginIDKeyConfig>;
  phoneInputConfig: Required<PhoneInputConfig>;
  setState: AppConfigFormModel<FormState>["setState"];
}

function PhoneSettings(props: PhoneSettingsProps) {
  const { phoneInputConfig, loginIDKeyConfigsControl, setState } = props;
  const { renderToString } = useContext(Context);

  const onChangePhoneList = useCallback(
    (allowlist: string[], pinnedList: string[]) => {
      setState((prev) =>
        produce(prev, (prev) => {
          prev.phoneInputConfig.allowlist = allowlist;
          prev.phoneInputConfig.pinned_list = pinnedList;
        })
      );
    },
    [setState]
  );

  const onChangePreselectByIP = useCallback(
    (_e, checked?: boolean) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.phoneInputConfig.preselect_by_ip_disabled = !checked;
        })
      );
    },
    [setState]
  );

  const onChangeModifyDisabled = useOnChangeModifyDisabled(setState, "phone");

  return (
    <Widget>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.phone.title" />
      </WidgetTitle>
      <WidgetDescription>
        <FormattedMessage id="LoginMethodConfigurationScreen.phone.description" />
      </WidgetDescription>
      <PhoneInputListWidget
        disabled={false}
        allowedAlpha2={phoneInputConfig.allowlist}
        pinnedAlpha2={phoneInputConfig.pinned_list}
        onChange={onChangePhoneList}
      />
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.phone.preselect-by-ip"
        )}
        checked={phoneInputConfig.preselect_by_ip_disabled !== true}
        onChange={onChangePreselectByIP}
      />
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.phone.modify-disabled"
        )}
        checked={
          loginIDKeyConfigsControl.find((a) => a.value.type === "phone")?.value
            .modify_disabled ?? false
        }
        onChange={onChangeModifyDisabled}
      />
    </Widget>
  );
}

function useUsernameConfigCheckboxOnChange(
  setState: AppConfigFormModel<FormState>["setState"],
  key: keyof LoginIDUsernameConfig
): ICheckboxProps["onChange"] {
  const onChange = useCallback(
    (_e, checked) => {
      if (checked == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.loginIDUsernameConfig[key] = checked;
        })
      );
    },
    [key, setState]
  );
  return onChange;
}

interface UsernameSettingsProps {
  resources: Partial<Record<string, Resource>>;
  loginIDKeyConfigsControl: ControlList<LoginIDKeyConfig>;
  loginIDUsernameConfig: Required<LoginIDUsernameConfig>;
  setState: AppConfigFormModel<FormState>["setState"];
}

function UsernameSettings(props: UsernameSettingsProps) {
  const {
    loginIDUsernameConfig,
    loginIDKeyConfigsControl,
    resources,
    setState,
  } = props;
  const { renderToString } = useContext(Context);

  const onChangeBlockReservedUsernames = useUsernameConfigCheckboxOnChange(
    setState,
    "block_reserved_usernames"
  );

  const onChangeExcludeKeywordsEnabled = useUsernameConfigCheckboxOnChange(
    setState,
    "exclude_keywords_enabled"
  );
  const {
    selectedItems: excludedKeywords,
    onChange: onChangeExcludedKeywords,
    onResolveSuggestions: onResolveSuggestionsExcludedKeywords,
    onAdd: onAddExcludedKeywords,
  } = useTagPickerWithNewTags(
    useLinesValue(resources, usernameExcludeKeywordsTXTSpecifier),
    useUpdateLinesValue(setState, usernameExcludeKeywordsTXTSpecifier)
  );

  const onChangeCaseSensitive = useUsernameConfigCheckboxOnChange(
    setState,
    "case_sensitive"
  );

  const onChangeASCIIOnly = useUsernameConfigCheckboxOnChange(
    setState,
    "ascii_only"
  );

  const onChangeModifyDisabled = useOnChangeModifyDisabled(
    setState,
    "username"
  );

  return (
    <Widget>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.username.title" />
      </WidgetTitle>
      <WidgetDescription>
        <FormattedMessage id="LoginMethodConfigurationScreen.username.description" />
      </WidgetDescription>
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.username.blockReservedUsername"
        )}
        checked={loginIDUsernameConfig.block_reserved_usernames}
        onChange={onChangeBlockReservedUsernames}
      />
      <CheckboxWithContentLayout>
        <CheckboxWithTooltip
          label={renderToString(
            "LoginIDConfigurationScreen.username.excludeKeywords"
          )}
          checked={loginIDUsernameConfig.exclude_keywords_enabled}
          onChange={onChangeExcludeKeywordsEnabled}
          tooltipMessageId="LoginIDConfigurationScreen.username.excludeKeywordsTooltipMessage"
        />
        <CustomTagPicker
          styles={fixTagPickerStyles}
          inputProps={{
            "aria-label": renderToString(
              "LoginIDConfigurationScreen.username.excludeKeywords"
            ),
          }}
          disabled={!loginIDUsernameConfig.exclude_keywords_enabled}
          selectedItems={excludedKeywords}
          onChange={onChangeExcludedKeywords}
          onResolveSuggestions={onResolveSuggestionsExcludedKeywords}
          onAdd={onAddExcludedKeywords}
        />
      </CheckboxWithContentLayout>
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.username.caseSensitive"
        )}
        checked={loginIDUsernameConfig.case_sensitive}
        onChange={onChangeCaseSensitive}
      />
      <Checkbox
        label={renderToString("LoginIDConfigurationScreen.username.asciiOnly")}
        checked={loginIDUsernameConfig.ascii_only}
        onChange={onChangeASCIIOnly}
      />
      <Checkbox
        label={renderToString(
          "LoginIDConfigurationScreen.username.modify-disabled"
        )}
        checked={
          loginIDKeyConfigsControl.find((a) => a.value.type === "username")
            ?.value.modify_disabled ?? false
        }
        onChange={onChangeModifyDisabled}
      />
    </Widget>
  );
}

function onRenderCriteriaLabel() {
  return (
    <LabelWithTooltip
      labelId="VerificationConfigurationScreen.criteria.label"
      tooltipMessageId="VerificationConfigurationScreen.criteria.tooltip"
      directionalHint={DirectionalHint.topCenter}
    />
  );
}

function useVerificationOnChangeRequired(
  setState: FormModel["setState"],
  key1: keyof VerificationClaimsConfig
) {
  return useCallback(
    (_, value) => {
      if (value == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.verificationConfig.claims ??= {};
          prev.verificationConfig.claims[key1] ??= {};
          // @ts-expect-error
          prev.verificationConfig.claims[key1].required = value;
          if (value) {
            // @ts-expect-error
            prev.verificationConfig.claims[key1].enabled = true;
          }
        })
      );
    },
    [setState, key1]
  );
}

function useVerificationOnChangeEnabled(
  setState: FormModel["setState"],
  key1: keyof VerificationClaimsConfig
) {
  return useCallback(
    (_, value) => {
      if (value == null) {
        return;
      }
      setState((prev) =>
        produce(prev, (prev) => {
          prev.verificationConfig.claims ??= {};
          prev.verificationConfig.claims[key1] ??= {};
          // @ts-expect-error
          prev.verificationConfig.claims[key1].enabled = value;
        })
      );
    },
    [setState, key1]
  );
}

interface VerificationSettingsProps {
  showEmailSettings: boolean;
  showPhoneSettings: boolean;
  verificationConfig: VerificationConfig;
  authenticatorOOBSMSConfig: AuthenticatorOOBSMSConfig;
  setState: FormModel["setState"];
}

// eslint-disable-next-line complexity
function VerificationSettings(props: VerificationSettingsProps) {
  const {
    showEmailSettings,
    showPhoneSettings,
    verificationConfig,
    setState,
    authenticatorOOBSMSConfig,
  } = props;

  const { renderToString } = useContext(Context);

  const onChangeCodeExpirySeconds = useCallback(
    (_, value) => {
      setState((prev) =>
        produce(prev, (prev) => {
          prev.verificationConfig.code_expiry_seconds =
            parseIntegerAllowLeadingZeros(value);
        })
      );
    },
    [setState]
  );

  const phoneOTPModes = useMemo(
    () =>
      authenticatorPhoneOTPModeList.map((mode) => ({
        key: mode,
        text: renderToString("AuthenticatorPhoneOTPMode." + mode),
      })),
    [renderToString]
  );
  const onChangePhoneOTPMode = useCallback(
    (_, option) => {
      const key = option.key as AuthenticatorPhoneOTPMode | undefined;
      if (key != null) {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.authenticatorOOBSMSConfig.phone_otp_mode = key;
          })
        );
      }
    },
    [setState]
  );

  const criteriaOptions = useMemo(
    () =>
      verificationCriteriaList.map((criteria) => ({
        key: criteria,
        text: renderToString(
          "VerificationConfigurationScreen.criteria." + criteria
        ),
      })),
    [renderToString]
  );
  const onChangeCriteria = useCallback(
    (_, option) => {
      const key = option.key as VerificationCriteria | undefined;
      if (key != null) {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.verificationConfig.criteria = key;
          })
        );
      }
    },
    [setState]
  );

  const onChangeEmailRequired = useVerificationOnChangeRequired(
    setState,
    "email"
  );
  const onChangeEmailEnabled = useVerificationOnChangeEnabled(
    setState,
    "email"
  );
  const onChangePhoneRequired = useVerificationOnChangeRequired(
    setState,
    "phone_number"
  );
  const onChangePhoneEnabled = useVerificationOnChangeEnabled(
    setState,
    "phone_number"
  );

  return (
    <Widget>
      <WidgetTitle>
        <FormattedMessage id="LoginMethodConfigurationScreen.verification.title" />
      </WidgetTitle>
      <WidgetDescription>
        <FormattedMessage id="LoginMethodConfigurationScreen.verification.description" />
      </WidgetDescription>
      <TextField
        type="text"
        label={renderToString(
          "VerificationConfigurationScreen.code-expiry-seconds.label"
        )}
        value={verificationConfig.code_expiry_seconds?.toFixed(0) ?? ""}
        onChange={onChangeCodeExpirySeconds}
      />
      {showEmailSettings && showPhoneSettings ? (
        <Dropdown
          options={criteriaOptions}
          selectedKey={verificationConfig.criteria}
          onChange={onChangeCriteria}
          onRenderLabel={onRenderCriteriaLabel}
        />
      ) : null}
      {showEmailSettings ? (
        <>
          <Toggle
            inlineLabel={true}
            checked={verificationConfig.claims?.email?.required ?? true}
            onChange={onChangeEmailRequired}
            label={renderToString(
              "VerificationConfigurationScreen.verification.email.required.label"
            )}
          />
          <Toggle
            inlineLabel={true}
            disabled={verificationConfig.claims?.email?.required ?? true}
            checked={verificationConfig.claims?.email?.enabled ?? true}
            onChange={onChangeEmailEnabled}
            label={renderToString(
              "VerificationConfigurationScreen.verification.email.allowed.label"
            )}
          />
        </>
      ) : null}
      {showPhoneSettings ? (
        <>
          <Toggle
            inlineLabel={true}
            checked={verificationConfig.claims?.phone_number?.required ?? true}
            onChange={onChangePhoneRequired}
            label={renderToString(
              "VerificationConfigurationScreen.verification.phone.required.label"
            )}
          />
          <Toggle
            inlineLabel={true}
            disabled={verificationConfig.claims?.phone_number?.required ?? true}
            checked={verificationConfig.claims?.phone_number?.enabled ?? true}
            onChange={onChangePhoneEnabled}
            label={renderToString(
              "VerificationConfigurationScreen.verification.phone.allowed.label"
            )}
          />
          <Dropdown
            label={renderToString(
              "VerificationConfigurationScreen.verification.phoneNumber.verify-by.label"
            )}
            options={phoneOTPModes}
            selectedKey={authenticatorOOBSMSConfig.phone_otp_mode}
            onChange={onChangePhoneOTPMode}
          />
        </>
      ) : null}
    </Widget>
  );
}

interface LoginMethodConfigurationContentProps {
  appID: string;
  form: FormModel;
}

const LoginMethodConfigurationContent: React.VFC<LoginMethodConfigurationContentProps> =
  // eslint-disable-next-line complexity
  function LoginMethodConfigurationContent(props) {
    const { appID } = props;
    const { state, setState } = props.form;

    const { renderToString } = useContext(Context);

    const {
      identitiesControl,
      primaryAuthenticatorsControl,
      loginIDKeyConfigsControl,
      loginIDEmailConfig,
      loginIDUsernameConfig,
      phoneInputConfig,
      verificationConfig,
      authenticatorOOBSMSConfig,
      authenticatorPasswordConfig,
      forgotPasswordConfig,
      passkeyChecked,

      phoneLoginIDDisabled,
      passwordPolicyFeatureConfig,

      resources,
    } = state;

    const [loginMethod, setLoginMethod] = useState(() =>
      loginMethodFromFormState(state)
    );

    const showEmailSettings = useMemo(
      () =>
        identitiesControl.find((a) => a.value === "login_id")?.isChecked ===
          true &&
        loginIDKeyConfigsControl.find((a) => a.value.type === "email")
          ?.isChecked === true,
      [identitiesControl, loginIDKeyConfigsControl]
    );
    const showPhoneSettings = useMemo(
      () =>
        identitiesControl.find((a) => a.value === "login_id")?.isChecked ===
          true &&
        loginIDKeyConfigsControl.find((a) => a.value.type === "phone")
          ?.isChecked === true,
      [identitiesControl, loginIDKeyConfigsControl]
    );
    const showUsernameSettings = useMemo(
      () =>
        identitiesControl.find((a) => a.value === "login_id")?.isChecked ===
          true &&
        loginIDKeyConfigsControl.find((a) => a.value.type === "username")
          ?.isChecked === true,
      [identitiesControl, loginIDKeyConfigsControl]
    );
    const showVerificationSettings = showEmailSettings || showPhoneSettings;

    const showPasswordSettings = useMemo(
      () =>
        primaryAuthenticatorsControl.find((a) => a.value === "password")
          ?.isChecked === true,
      [primaryAuthenticatorsControl]
    );

    const onChangeLoginMethod = useCallback(
      (loginMethod: LoginMethod) => {
        setLoginMethod(loginMethod);
        setState((prev) =>
          produce(prev, (prev) => {
            setLoginMethodToFormState(prev, loginMethod);
          })
        );
      },
      [setState]
    );

    const onChangePasskeyChecked = useCallback(
      (_e, checked) => {
        if (checked == null) {
          return;
        }
        setState((prev) =>
          produce(prev, (prev) => {
            prev.passkeyChecked = checked;
          })
        );
      },
      [setState]
    );

    const onChangeLoginIDChecked = useCallback(
      (typ: LoginIDKeyType, checked: boolean) => {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.loginIDKeyConfigsControl = controlListCheckWithPlainValue(
              (a, b) => a === b.type,
              typ,
              checked,
              prev.loginIDKeyConfigsControl
            );
            correctCurrentFormState(prev);
          })
        );
      },
      [setState]
    );

    const onSwapLoginID = useCallback(
      (index1: number, index2: number) => {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.loginIDKeyConfigsControl = controlListSwap(
              index1,
              index2,
              prev.loginIDKeyConfigsControl
            );
          })
        );
      },
      [setState]
    );

    const onChangePrimaryAuthenticatorChecked = useCallback(
      (typ: PrimaryAuthenticatorType, checked: boolean) => {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.primaryAuthenticatorsControl = controlListCheckWithPlainValue(
              (a, b) => a === b,
              typ,
              checked,
              prev.primaryAuthenticatorsControl
            );
          })
        );
      },
      [setState]
    );

    const onSwapPrimaryAuthenticator = useCallback(
      (index1: number, index2: number) => {
        setState((prev) =>
          produce(prev, (prev) => {
            prev.primaryAuthenticatorsControl = controlListSwap(
              index1,
              index2,
              prev.primaryAuthenticatorsControl
            );
          })
        );
      },
      [setState]
    );

    return (
      <ScreenContent>
        <ScreenTitle className={styles.widget}>
          <FormattedMessage id="LoginMethodConfigurationScreen.title" />
        </ScreenTitle>
        <ShowOnlyIfSIWEIsDisabled className={styles.widget}>
          <ChosenLoginMethod
            loginMethod={loginMethod}
            passkeyChecked={passkeyChecked}
          />
          <LoginMethodChooser
            loginMethod={loginMethod}
            phoneLoginIDDisabled={phoneLoginIDDisabled}
            passkeyChecked={passkeyChecked}
            onChangePasskeyChecked={onChangePasskeyChecked}
            appID={appID}
            onChangeLoginMethod={onChangeLoginMethod}
          />
          {/* Pivot is intentionally uncontrolled */}
          {/* It is because it is troublesome to keep track of the selected key */}
          {/* And making it controlled does not bring any benefits */}
          <Pivot
            className={styles.widget}
            styles={PIVOT_STYLES}
            overflowBehavior="menu"
          >
            {loginMethod === "custom" ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.pivot.custom.title"
                )}
                itemKey="custom"
              >
                <CustomLoginMethods
                  phoneLoginIDDisabled={phoneLoginIDDisabled}
                  primaryAuthenticatorsControl={primaryAuthenticatorsControl}
                  loginIDKeyConfigsControl={loginIDKeyConfigsControl}
                  onChangeLoginIDChecked={onChangeLoginIDChecked}
                  onSwapLoginID={onSwapLoginID}
                  onChangePrimaryAuthenticatorChecked={
                    onChangePrimaryAuthenticatorChecked
                  }
                  onSwapPrimaryAuthenticator={onSwapPrimaryAuthenticator}
                />
              </PivotItem>
            ) : null}
            {showEmailSettings ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.pivot.email.title"
                )}
                itemKey="email"
              >
                <EmailSettings
                  resources={resources}
                  loginIDKeyConfigsControl={loginIDKeyConfigsControl}
                  loginIDEmailConfig={loginIDEmailConfig}
                  setState={setState}
                />
              </PivotItem>
            ) : null}
            {showPhoneSettings ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.pivot.phone.title"
                )}
                itemKey="phone"
              >
                <PhoneSettings
                  loginIDKeyConfigsControl={loginIDKeyConfigsControl}
                  phoneInputConfig={phoneInputConfig}
                  setState={setState}
                />
              </PivotItem>
            ) : null}
            {showUsernameSettings ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.pivot.username.title"
                )}
                itemKey="username"
              >
                <UsernameSettings
                  resources={resources}
                  loginIDKeyConfigsControl={loginIDKeyConfigsControl}
                  loginIDUsernameConfig={loginIDUsernameConfig}
                  setState={setState}
                />
              </PivotItem>
            ) : null}
            {showVerificationSettings ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.pivot.verification.title"
                )}
                itemKey="verification"
              >
                <VerificationSettings
                  showEmailSettings={showEmailSettings}
                  showPhoneSettings={showPhoneSettings}
                  verificationConfig={verificationConfig}
                  authenticatorOOBSMSConfig={authenticatorOOBSMSConfig}
                  setState={setState}
                />
              </PivotItem>
            ) : null}
            {showPasswordSettings ? (
              <PivotItem
                headerText={renderToString(
                  "LoginMethodConfigurationScreen.password.title"
                )}
                itemKey="password"
              >
                <PasswordSettings
                  forgotPasswordConfig={forgotPasswordConfig}
                  authenticatorPasswordConfig={authenticatorPasswordConfig}
                  passwordPolicyFeatureConfig={passwordPolicyFeatureConfig}
                  setState={setState}
                />
              </PivotItem>
            ) : null}
          </Pivot>
        </ShowOnlyIfSIWEIsDisabled>
      </ScreenContent>
    );
  };

const LoginMethodConfigurationScreen: React.VFC =
  function LoginMethodConfigurationScreen() {
    const { appID } = useParams() as { appID: string };

    const featureConfig = useAppFeatureConfigQuery(appID);

    const configForm = useAppConfigForm({
      appID,
      constructFormState,
      constructConfig,
    });

    const resourceForm = useResourceForm(
      appID,
      specifiers,
      constructResourcesFormState,
      constructResources
    );

    const state = useMemo<FormState>(() => {
      return {
        resources: resourceForm.state.resources,
        phoneLoginIDDisabled:
          featureConfig.effectiveFeatureConfig?.identity?.login_id?.types?.phone
            ?.disabled ?? false,
        passwordPolicyFeatureConfig:
          featureConfig.effectiveFeatureConfig?.authenticator?.password?.policy,
        ...configForm.state,
      };
    }, [
      resourceForm.state.resources,
      featureConfig.effectiveFeatureConfig?.identity?.login_id?.types?.phone
        ?.disabled,
      featureConfig.effectiveFeatureConfig?.authenticator?.password?.policy,
      configForm.state,
    ]);

    const form: FormModel = {
      isLoading:
        configForm.isLoading || resourceForm.isLoading || featureConfig.loading,
      isUpdating: configForm.isUpdating || resourceForm.isUpdating,
      isDirty: configForm.isDirty || resourceForm.isDirty,
      loadError:
        configForm.loadError ?? resourceForm.loadError ?? featureConfig.error,
      updateError: configForm.updateError ?? resourceForm.updateError,
      state,
      setState: (fn) => {
        const newState = fn(state);
        const { phoneLoginIDDisabled, resources, ...rest } = newState;
        configForm.setState(() => rest);
        resourceForm.setState(() => ({ resources }));
      },
      reload: () => {
        configForm.reload();
        resourceForm.reload();
        featureConfig.refetch().finally(() => {});
      },
      reset: () => {
        configForm.reset();
        resourceForm.reset();
      },
      save: async () => {
        await configForm.save();
        await resourceForm.save();
      },
    };

    if (form.isLoading) {
      return <ShowLoading />;
    }

    if (form.loadError) {
      return <ShowError error={form.loadError} onRetry={form.reload} />;
    }

    return (
      <FormContainer form={form} errorRules={ERROR_RULES}>
        <LoginMethodConfigurationContent appID={appID} form={form} />
      </FormContainer>
    );
  };

export default LoginMethodConfigurationScreen;
