import { Navigate, useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import EndpointEditor from "../features/flow/EndpointEditor";
import EndpointSidebar from "../features/flow/EndpointSidebar";
import StackPanel from "../features/flow/StackPanel";
import { useScanStore } from "../store/scanStore";

function EndpointPage() {
  const navigate = useNavigate();
  const common = useScanStore((state) => state.common);
  const requests = useScanStore((state) => state.endpointRequests);
  const selectedId = useScanStore((state) => state.selectedEndpointId);
  const stack = useScanStore((state) => state.stack);
  const setStack = useScanStore((state) => state.setStack);
  const addRequest = useScanStore((state) => state.addEndpointRequest);
  const updateRequest = useScanStore((state) => state.updateEndpointRequest);
  const removeRequest = useScanStore((state) => state.removeEndpointRequest);
  const selectRequest = useScanStore((state) => state.selectEndpointRequest);
  const addParamRow = useScanStore((state) => state.addParamRow);
  const updateParamRow = useScanStore((state) => state.updateParamRow);
  const removeParamRow = useScanStore((state) => state.removeParamRow);
  const activeRequest = requests.find((request) => request.id === selectedId) ?? requests[0];

  if (!common.baseUrl.trim()) return <Navigate replace to="/setup" />;
  if (!activeRequest) return <Navigate replace to="/setup" />;

  return (
    <AppFrame eyebrow="Endpoint Scan">
      <div className="grid gap-6 xl:grid-cols-[340px_minmax(0,1fr)]">
        <EndpointSidebar requests={requests} selectedId={activeRequest.id} onAdd={addRequest} onSelect={selectRequest} />
        <div className="space-y-6">
          <EndpointEditor
            baseUrl={common.baseUrl}
            request={activeRequest}
            onRemove={() => removeRequest(activeRequest.id)}
            onChange={(key, value) => updateRequest(activeRequest.id, { [key]: value } as Partial<typeof activeRequest>)}
            onAddParam={(group) => addParamRow(activeRequest.id, group)}
            onChangeParam={(group, paramId, key, value) => updateParamRow(activeRequest.id, group, paramId, { [key]: value })}
            onRemoveParam={(group, paramId) => removeParamRow(activeRequest.id, group, paramId)}
          />
          <StackPanel
            stack={stack}
            errorMessage=""
            onPatch={setStack}
          />
          <div className="flex justify-between">
            <button type="button" onClick={() => navigate("/setup")} className="rounded-full border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700">이전</button>
            <button type="button" onClick={() => navigate("/run")} className="rounded-full bg-sky-500 px-5 py-3 text-sm font-semibold text-white">실행 준비</button>
          </div>
        </div>
      </div>
    </AppFrame>
  );
}

export default EndpointPage;
