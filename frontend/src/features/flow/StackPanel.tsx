import type { StackConfig } from "../../types/scan";

type Props = {
  stack: StackConfig;
  errorMessage: string;
  onPatch: (patch: Partial<StackConfig>) => void;
};

function StackPanel({ stack, errorMessage, onPatch }: Props) {
  return (
    <section className="rounded-[28px] border border-slate-200 bg-white/88 p-6 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
      <div className="space-y-6">
        <div className="border-b border-slate-200 pb-5">
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.24em] text-sky-700/80">
              Enter stack information
            </p>
            <h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-slate-950">
              사용 기술 / 프레임 워크 정보 입력
            </h2>
          </div>
        </div>

        <label className="space-y-2">
          <span className="text-sm font-medium text-slate-700">stack_name</span>
          <input
            className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400/50"
            placeholder="React, Django, Node ..."
            value={stack.stackName}
            onChange={(event) => onPatch({ stackName: event.target.value })}
          />
        </label>

        {errorMessage ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {errorMessage}
          </div>
        ) : null}
      </div>
    </section>
  );
}

export default StackPanel;
