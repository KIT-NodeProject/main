import { methodTone } from "../../lib/request";
import type { EndpointRequestDraft } from "../../types/scan";

type Props = {
  requests: EndpointRequestDraft[];
  selectedId: string;
  onAdd: () => void;
  onSelect: (id: string) => void;
};

function EndpointSidebar({ requests, selectedId, onAdd, onSelect }: Props) {
  return (
    <aside className="rounded-[28px] border border-slate-200 bg-white/85 p-4 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
      <div className="flex items-center justify-between px-2 pb-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Collection</p>
          <h2 className="mt-2 text-xl font-semibold text-slate-950">Endpoint Requests</h2>
        </div>
        <button
          type="button"
          onClick={onAdd}
          className="rounded-full border border-sky-200 bg-sky-50 px-3 py-2 text-xs font-semibold text-sky-800 transition hover:border-sky-300 hover:bg-sky-100"
        >
          + 요청 추가
        </button>
      </div>
      <div className="space-y-3">
        {requests.map((request, index) => (
          <button
            key={request.id}
            type="button"
            onClick={() => onSelect(request.id)}
            className={[
              "w-full rounded-3xl border p-4 text-left transition",
              request.id === selectedId
                ? "border-sky-300 bg-sky-50"
                : "border-slate-200 bg-white hover:border-sky-200 hover:bg-slate-50",
            ].join(" ")}
          >
            <div className="flex items-center gap-2">
              <span
                className={[
                  "rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1",
                  methodTone(request.method),
                ].join(" ")}
              >
                {request.method}
              </span>
              <span className="text-xs text-slate-500">#{index + 1}</span>
            </div>
            <p className="mt-3 truncate text-sm font-semibold text-slate-950">{request.name}</p>
            <p className="mt-1 truncate text-xs text-slate-500">{request.path || "/path"}</p>
          </button>
        ))}
      </div>
    </aside>
  );
}

export default EndpointSidebar;
