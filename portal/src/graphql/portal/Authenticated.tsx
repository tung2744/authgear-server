import React, { useEffect } from "react";
import authgear from "@authgear/web";
import ShowError from "../../ShowError";
import ShowLoading from "../../ShowLoading";
import { useViewerQuery } from "./query/viewerQuery";

interface ShowQueryResultProps {
  isAuthenticated: boolean;
  children?: React.ReactElement;
}

function encodeOAuthState(state: Record<string, unknown>): string {
  return btoa(JSON.stringify(state));
}

const ShowQueryResult: React.VFC<ShowQueryResultProps> =
  function ShowQueryResult(props: ShowQueryResultProps) {
    const { isAuthenticated } = props;

    const redirectURI = window.location.origin + "/oauth-redirect";
    const originalPath = `${window.location.pathname}${window.location.search}`;

    useEffect(() => {
      if (!isAuthenticated) {
        // Normally we should call endAuthorization after being redirected back to here.
        // But we know that we are first party app and are using response_type=none so
        // we can skip that.
        authgear
          .startAuthentication({
            redirectURI,
            prompt: "login",
            state: encodeOAuthState({
              originalPath,
            }),
          })
          .catch((err) => {
            console.error(err);
          });
      }
    }, [isAuthenticated, redirectURI, originalPath]);

    if (isAuthenticated) {
      return props.children ?? null;
    }

    return null;
  };

interface Props {
  children?: React.ReactElement;
}

// CAVEAT: <Authenticated><Route path="/foobar/:id"/></Authenticated> will cause useParams to return empty object :(
const Authenticated: React.VFC<Props> = function Authenticated(
  ownProps: Props
) {
  const { loading, error, viewer, refetch } = useViewerQuery();

  if (loading) {
    return <ShowLoading />;
  }

  if (error != null) {
    return <ShowError error={error} onRetry={refetch} />;
  }

  return <ShowQueryResult isAuthenticated={viewer != null} {...ownProps} />;
};

export async function startReauthentication<S>(state?: S): Promise<void> {
  await authgear.refreshIDToken();
  const redirectURI = window.location.origin + "/oauth-redirect";
  const originalPath = `${window.location.pathname}${window.location.search}`;
  await authgear.startReauthentication({
    redirectURI,
    state: encodeOAuthState({
      originalPath,
      state,
    }),
  });
}

export default Authenticated;
