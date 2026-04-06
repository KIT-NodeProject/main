import type {
  EndpointRequestDraft,
  HttpMethod,
  ParamDraft,
  TargetRunPayload,
} from "../types/scan";

const METHOD_OPTIONS: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

const FALLBACK_ID_PREFIX = "draft";

function makeId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${FALLBACK_ID_PREFIX}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export { METHOD_OPTIONS };

export function createParamDraft(): ParamDraft {
  return {
    id: makeId(),
    key: "",
    value: "",
  };
}

export function createEndpointRequestDraft(index: number): EndpointRequestDraft {
  return {
    id: makeId(),
    name: `Endpoint ${index}`,
    method: "GET",
    path: "",
    requiresAuth: false,
    queryParams: [createParamDraft()],
    bodyParams: [createParamDraft()],
  };
}

type NormalizedEndpointResult =
  | { isValid: true; normalized: string }
  | { isValid: false; message: string };

export function normalizeEndpoint(baseUrl: string, rawEndpoint: string): NormalizedEndpointResult {
  const trimmedEndpoint = rawEndpoint.trim();
  if (!trimmedEndpoint) {
    return { isValid: false, message: "엔드포인트 경로를 입력해주세요." };
  }
  if (trimmedEndpoint.startsWith("/")) {
    return { isValid: true, normalized: trimmedEndpoint };
  }

  try {
    const base = new URL(baseUrl);
    const endpointUrl = new URL(trimmedEndpoint);
    if (base.origin !== endpointUrl.origin) {
      return {
        isValid: false,
        message: "엔드포인트는 입력한 사이트와 같은 도메인만 사용할 수 있습니다.",
      };
    }
    return {
      isValid: true,
      normalized: `${endpointUrl.pathname}${endpointUrl.search}${endpointUrl.hash}`,
    };
  } catch {
    return {
      isValid: false,
      message: "엔드포인트는 /path 또는 같은 사이트의 전체 URL로 입력해주세요.",
    };
  }
}

export function composeRequestUrl(baseUrl: string, path: string) {
  const trimmedPath = path.trim();
  if (!trimmedPath) {
    return baseUrl;
  }
  if (trimmedPath.startsWith("http")) {
    return trimmedPath;
  }
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const nextPath = trimmedPath.startsWith("/") ? trimmedPath : `/${trimmedPath}`;
  return `${base}${nextPath}`;
}

function compactParams(params: ParamDraft[]) {
  return params.reduce<Record<string, string>>((acc, param) => {
    const key = param.key.trim();
    const value = param.value.trim();
    if (key) {
      acc[key] = value;
    }
    return acc;
  }, {});
}

export function buildTargetRunPayload(input: TargetRunPayload): TargetRunPayload {
  return {
    ...input,
    endpoint_scan: {
      ...input.endpoint_scan,
      requests: input.endpoint_scan.requests.map((request) => ({
        ...request,
      })),
    },
    stack_scan: {
      ...input.stack_scan,
    },
  };
}

export function buildAdapterPayload(payload: TargetRunPayload) {
  const normalizedRequests = payload.endpoint_scan.requests
    .filter((request) => request.path.trim())
    .map((request) => request.path.trim());

  return {
    base_url: payload.common.baseUrl.trim(),
    stack_name: payload.stack_scan.stack_name.trim(),
    login_required: payload.common.loginRequired,
    auth_mode: payload.common.authMode,
    endpoint_scan: payload.endpoint_scan,
    stack_scan: payload.stack_scan,
    endpoints: normalizedRequests,
  };
}

export function serializeEndpointRequest(request: EndpointRequestDraft) {
  return {
    method: request.method,
    path: request.path.trim(),
    endpoint_type: request.requiresAuth ? "login_required" : "public",
    requires_auth: request.requiresAuth,
    query_params: compactParams(request.queryParams),
    body_params: compactParams(request.bodyParams),
  };
}

export function methodTone(method: HttpMethod) {
  switch (method) {
    case "GET":
      return "bg-emerald-100 text-emerald-800 ring-emerald-200";
    case "POST":
      return "bg-sky-100 text-sky-800 ring-sky-200";
    case "PUT":
      return "bg-amber-100 text-amber-800 ring-amber-200";
    case "PATCH":
      return "bg-fuchsia-100 text-fuchsia-800 ring-fuchsia-200";
    case "DELETE":
      return "bg-rose-100 text-rose-800 ring-rose-200";
    default:
      return "bg-slate-100 text-slate-700 ring-slate-200";
  }
}
