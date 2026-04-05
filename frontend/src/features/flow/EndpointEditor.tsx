import { METHOD_OPTIONS, composeRequestUrl } from "../../lib/request";
import type { EndpointRequestDraft } from "../../types/scan";
import ParamTable from "./ParamTable";

type Props = {
  baseUrl: string;
  request: EndpointRequestDraft;
  onRemove: () => void;
  onChange: <Key extends keyof EndpointRequestDraft>(key: Key, value: EndpointRequestDraft[Key]) => void;
  onAddParam: (group: "queryParams" | "bodyParams") => void;
  onChangeParam: (
    group: "queryParams" | "bodyParams",
    paramId: string,
    key: "key" | "value",
    value: string,
  ) => void;
  onRemoveParam: (group: "queryParams" | "bodyParams", paramId: string) => void;
};

function EndpointEditor({
  baseUrl,
  request,
  onRemove,
  onChange,
  onAddParam,
  onChangeParam,
  onRemoveParam,
}: Props) {
  return (
    <section className="space-y-6">
      <div className="rounded-[28px] border border-slate-200 bg-white/88 p-6 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
        <div className="flex flex-col gap-4 border-b border-slate-200 pb-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Endpoint Setup</p>
            <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950">
              {request.name}
            </h2>
          </div>
          <button
            type="button"
            onClick={onRemove}
            className="rounded-full border border-rose-200 bg-rose-50 px-4 py-2 text-sm text-rose-700"
          >
            현재 요청 제거
          </button>
        </div>

        <div className="mt-6 space-y-5">
          <div className="grid gap-4 lg:grid-cols-[1fr_180px_1fr]">
            <label className="space-y-2">
              <span className="text-sm font-medium text-slate-700">이름</span>
              <input
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
                value={request.name}
                onChange={(event) => onChange("name", event.target.value)}
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm font-medium text-slate-700">Method</span>
              <select
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
                value={request.method}
                onChange={(event) => onChange("method", event.target.value as EndpointRequestDraft["method"])}
              >
                {METHOD_OPTIONS.map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-2">
              <span className="text-sm font-medium text-slate-700">Path</span>
              <input
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
                placeholder="/api/v1/users/123"
                value={request.path}
                onChange={(event) => onChange("path", event.target.value)}
              />
            </label>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Full URL Preview: <span className="font-medium text-slate-950">{composeRequestUrl(baseUrl, request.path)}</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => onChange("requiresAuth", !request.requiresAuth)}
              className={[
                "rounded-full border px-4 py-2 text-sm transition",
                request.requiresAuth
                  ? "border-amber-200 bg-amber-50 text-amber-800"
                  : "border-slate-200 bg-white text-slate-600",
              ].join(" ")}
            >
              {request.requiresAuth ? "인증 필요" : "인증 불필요"}
            </button>
          </div>
        </div>
      </div>

      <div className="grid gap-4">
        <ParamTable
          title="Query Params"
          params={request.queryParams}
          onAdd={() => onAddParam("queryParams")}
          onChange={(paramId, key, value) => onChangeParam("queryParams", paramId, key, value)}
          onRemove={(paramId) => onRemoveParam("queryParams", paramId)}
        />
        <ParamTable
          title="Body Params"
          params={request.bodyParams}
          onAdd={() => onAddParam("bodyParams")}
          onChange={(paramId, key, value) => onChangeParam("bodyParams", paramId, key, value)}
          onRemove={(paramId) => onRemoveParam("bodyParams", paramId)}
        />
      </div>
    </section>
  );
}

export default EndpointEditor;
