import type { ParamDraft } from "../../types/scan";

type Props = {
  title: string;
  params: ParamDraft[];
  onAdd: () => void;
  onChange: (paramId: string, key: "key" | "value", value: string) => void;
  onRemove: (paramId: string) => void;
};

function ParamTable({ title, params, onAdd, onChange, onRemove }: Props) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-slate-50/80 p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-slate-800">{title}</p>
        <button
          type="button"
          onClick={onAdd}
          className="rounded-full border border-sky-200 bg-white px-3 py-1 text-xs font-semibold text-sky-800"
        >
          + 행 추가
        </button>
      </div>
      <div className="mt-4 space-y-3">
        {params.map((param) => (
          <div key={param.id} className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
            <input
              className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
              placeholder="key"
              value={param.key}
              onChange={(event) => onChange(param.id, "key", event.target.value)}
            />
            <input
              className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
              placeholder="value"
              value={param.value}
              onChange={(event) => onChange(param.id, "value", event.target.value)}
            />
            <button
              type="button"
              onClick={() => onRemove(param.id)}
              className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700"
            >
              삭제
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ParamTable;
