import React, { useCallback, useMemo, useContext } from "react";
import { useParams } from "react-router-dom";
import { Context, FormattedMessage } from "@oursky/react-messageformat";

import { useAppAndSecretConfigQuery } from "../portal/query/appAndSecretConfigQuery";
import { useUserQuery } from "./query/userQuery";
import NavBreadcrumb from "../../NavBreadcrumb";
import FormTextField from "../../FormTextField";
import AddIdentityForm from "./AddIdentityForm";
import ShowLoading from "../../ShowLoading";
import ShowError from "../../ShowError";
import {
  ErrorParseRule,
  makeInvariantViolatedErrorParseRule,
} from "../../error/parse";

import styles from "./AddUsernameScreen.module.css";

const errorRules: ErrorParseRule[] = [
  makeInvariantViolatedErrorParseRule(
    "DuplicatedIdentity",
    "AddUsernameScreen.error.duplicated-username"
  ),
];

interface UsernameFieldProps {
  value: string;
  onChange: (value: string) => void;
}

const UsernameField: React.VFC<UsernameFieldProps> = function UsernameField(
  props
) {
  const { value, onChange } = props;
  const { renderToString } = useContext(Context);
  const onUsernameChange = useCallback(
    (_, value?: string) => onChange(value ?? ""),
    [onChange]
  );
  return (
    <FormTextField
      parentJSONPointer=""
      fieldName="login_id"
      label={renderToString("AddUsernameScreen.username.label")}
      className={styles.widget}
      value={value}
      onChange={onUsernameChange}
      errorRules={errorRules}
    />
  );
};

const AddUsernameScreen: React.VFC = function AddUsernameScreen() {
  const { appID, userID } = useParams() as { appID: string; userID: string };
  const {
    user,
    loading: loadingUser,
    error: userError,
    refetch: refetchUser,
  } = useUserQuery(userID);
  const {
    effectiveAppConfig,
    loading: loadingAppConfig,
    error: appConfigError,
    refetch: refetchAppConfig,
  } = useAppAndSecretConfigQuery(appID);

  const navBreadcrumbItems = useMemo(() => {
    return [
      { to: "~/users", label: <FormattedMessage id="UsersScreen.title" /> },
      {
        to: `~/users/${user?.id}/details`,
        label: <FormattedMessage id="UserDetailsScreen.title" />,
      },
      { to: ".", label: <FormattedMessage id="AddUsernameScreen.title" /> },
    ];
  }, [user?.id]);
  const title = (
    <NavBreadcrumb className={styles.widget} items={navBreadcrumbItems} />
  );

  if (loadingUser || loadingAppConfig) {
    return <ShowLoading />;
  }

  if (userError != null) {
    return <ShowError error={userError} onRetry={refetchUser} />;
  }

  if (appConfigError != null) {
    return <ShowError error={appConfigError} onRetry={refetchAppConfig} />;
  }

  return (
    <AddIdentityForm
      appConfig={effectiveAppConfig}
      rawUser={user}
      loginIDType="username"
      title={title}
      loginIDField={UsernameField}
    />
  );
};

export default AddUsernameScreen;
