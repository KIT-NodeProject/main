export type ScanResultItem = {
  poc_name: string;
  status: string;
  description: string;
  evidence: string;
  raw_output: string;
  debug_log?: string;
  vulnerable: boolean;
};

export type StackScanResponse = {
  scan_id: string;
  status: string;
  base_url: string;
  stack_name: string;
  results: ScanResultItem[];
};

export type EndpointScanConfigItem = {
  id: number;
  path: string;
  method?: HttpMethod;
  endpoint_type: "public" | "login_required" | "login_page";
};

export type EndpointScanResultItem = ScanResultItem & {
  endpoint_id: number;
};

export type EndpointScanResponse = {
  scan_id: string;
  status: string;
  base_url: string;
  endpoints: EndpointScanConfigItem[];
  results: EndpointScanResultItem[];
};

export type ScanResult = {
  executed_targets: Array<"stack" | "endpoint">;
  stack_scan?: StackScanResponse;
  endpoint_scans?: EndpointScanResponse[];
};

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "OPTIONS";

export type AuthMode = "none" | "session" | "bearer" | "basic";

export type ParamDraft = {
  id: string;
  key: string;
  value: string;
};

export type CommonConfig = {
  baseUrl: string;
  loginRequired: boolean;
  authMode: AuthMode;
};

export type ScanTargets = {
  endpointEnabled: boolean;
  stackEnabled: boolean;
};

export type EndpointRequestDraft = {
  id: string;
  name: string;
  method: HttpMethod;
  path: string;
  requiresAuth: boolean;
  queryParams: ParamDraft[];
  bodyParams: ParamDraft[];
};

export type StackConfig = {
  stackName: string;
};

export type TargetRunPayload = {
  common: CommonConfig;
  targets: ScanTargets;
  endpoint_scan: {
    enabled: boolean;
    requests: Array<{
      method: HttpMethod;
      path: string;
      endpoint_type?: "public" | "login_required" | "login_page";
      requires_auth?: boolean;
      query_params: Record<string, string>;
      body_params: Record<string, string>;
    }>;
  };
  stack_scan: {
    enabled: boolean;
    stack_name: string;
  };
};
