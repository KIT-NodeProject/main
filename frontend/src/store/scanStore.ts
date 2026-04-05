import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";
import { createEndpointRequestDraft, createParamDraft } from "../lib/request";
import type {
  CommonConfig,
  EndpointRequestDraft,
  ParamDraft,
  ScanResult,
  ScanTargets,
  StackConfig,
} from "../types/scan";

type ParamGroupKey = "queryParams" | "bodyParams";

type ScanStore = {
  common: CommonConfig;
  targets: ScanTargets;
  endpointRequests: EndpointRequestDraft[];
  selectedEndpointId: string;
  stack: StackConfig;
  scanResult?: ScanResult;
  isSubmitting: boolean;
  setCommon: (patch: Partial<CommonConfig>) => void;
  setTargets: (patch: Partial<ScanTargets>) => void;
  setStack: (patch: Partial<StackConfig>) => void;
  addEndpointRequest: () => void;
  updateEndpointRequest: (id: string, patch: Partial<EndpointRequestDraft>) => void;
  removeEndpointRequest: (id: string) => void;
  selectEndpointRequest: (id: string) => void;
  addParamRow: (requestId: string, group: ParamGroupKey) => void;
  updateParamRow: (
    requestId: string,
    group: ParamGroupKey,
    paramId: string,
    patch: Partial<ParamDraft>,
  ) => void;
  removeParamRow: (requestId: string, group: ParamGroupKey, paramId: string) => void;
  setScanResult: (result?: ScanResult) => void;
  setSubmitting: (value: boolean) => void;
  resetAll: () => void;
};

const initialRequest = createEndpointRequestDraft(1);

const initialCommon: CommonConfig = {
  baseUrl: "",
  loginRequired: false,
  authMode: "none",
};

const initialTargets: ScanTargets = {
  endpointEnabled: true,
  stackEnabled: true,
};

const initialStack: StackConfig = {
  stackName: "",
};

function buildInitialState() {
  return {
    common: initialCommon,
    targets: initialTargets,
    endpointRequests: [initialRequest],
    selectedEndpointId: initialRequest.id,
    stack: initialStack,
    scanResult: undefined as ScanResult | undefined,
    isSubmitting: false,
  };
}

function ensureAtLeastOneRow(params: ParamDraft[]) {
  return params.length > 0 ? params : [createParamDraft()];
}

export const useScanStore = create<ScanStore>()(
  persist(
    (set) => ({
      ...buildInitialState(),
      setCommon: (patch) => set((state) => ({ common: { ...state.common, ...patch } })),
      setTargets: (patch) => set((state) => ({ targets: { ...state.targets, ...patch } })),
      setStack: (patch) => set((state) => ({ stack: { ...state.stack, ...patch } })),
      addEndpointRequest: () =>
        set((state) => {
          const nextRequest = createEndpointRequestDraft(state.endpointRequests.length + 1);
          return {
            endpointRequests: [...state.endpointRequests, nextRequest],
            selectedEndpointId: nextRequest.id,
          };
        }),
      updateEndpointRequest: (id, patch) =>
        set((state) => ({
          endpointRequests: state.endpointRequests.map((request) =>
            request.id === id ? { ...request, ...patch } : request,
          ),
        })),
      removeEndpointRequest: (id) =>
        set((state) => {
          if (state.endpointRequests.length === 1) {
            const nextRequest = createEndpointRequestDraft(1);
            return {
              endpointRequests: [nextRequest],
              selectedEndpointId: nextRequest.id,
            };
          }
          const nextRequests = state.endpointRequests.filter((request) => request.id !== id);
          const hasSelected = nextRequests.some((request) => request.id === state.selectedEndpointId);
          return {
            endpointRequests: nextRequests,
            selectedEndpointId: hasSelected ? state.selectedEndpointId : nextRequests[0]?.id ?? "",
          };
        }),
      selectEndpointRequest: (id) => set({ selectedEndpointId: id }),
      addParamRow: (requestId, group) =>
        set((state) => ({
          endpointRequests: state.endpointRequests.map((request) =>
            request.id === requestId
              ? { ...request, [group]: [...request[group], createParamDraft()] }
              : request,
          ),
        })),
      updateParamRow: (requestId, group, paramId, patch) =>
        set((state) => ({
          endpointRequests: state.endpointRequests.map((request) =>
            request.id === requestId
              ? {
                  ...request,
                  [group]: request[group].map((param) =>
                    param.id === paramId ? { ...param, ...patch } : param,
                  ),
                }
              : request,
          ),
        })),
      removeParamRow: (requestId, group, paramId) =>
        set((state) => ({
          endpointRequests: state.endpointRequests.map((request) =>
            request.id === requestId
              ? {
                  ...request,
                  [group]: ensureAtLeastOneRow(
                    request[group].filter((param) => param.id !== paramId),
                  ),
                }
              : request,
          ),
        })),
      setScanResult: (result) => set({ scanResult: result }),
      setSubmitting: (value) => set({ isSubmitting: value }),
      resetAll: () => set({ ...buildInitialState() }),
    }),
    {
      name: "scan-flow-workbench",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        common: state.common,
        targets: state.targets,
        endpointRequests: state.endpointRequests,
        selectedEndpointId: state.selectedEndpointId,
        stack: state.stack,
        scanResult: state.scanResult,
      }),
    },
  ),
);
