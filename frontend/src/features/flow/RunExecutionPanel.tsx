type RunStep = {
  id: string;
  label: string;
  description: string;
};

type Props = {
  steps: RunStep[];
  activeIndex: number;
  started: boolean;
  completed: boolean;
  isSubmitting: boolean;
  errorMessage: string;
  onExecute: () => void;
};

function stepTone(index: number, activeIndex: number, started: boolean, completed: boolean) {
  if (completed || (started && index < activeIndex)) {
    return "border-emerald-200 bg-emerald-50";
  }
  if (started && index === activeIndex) {
    return "border-sky-200 bg-sky-50";
  }
  return "border-slate-200 bg-white";
}

function indicator(index: number, activeIndex: number, started: boolean, completed: boolean) {
  if (completed || (started && index < activeIndex)) {
    return <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500 text-sm font-bold text-white animate-[pop-in_0.35s_ease-out]">✓</span>;
  }
  if (started && index === activeIndex) {
    return (
      <span className="inline-flex h-8 w-8 items-center justify-center rounded-full border-2 border-sky-500 border-t-transparent animate-spin" />
    );
  }
  return <span className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-slate-200 bg-slate-50 text-sm font-semibold text-slate-500">{index + 1}</span>;
}

function RunExecutionPanel({
  steps,
  activeIndex,
  started,
  completed,
  isSubmitting,
  errorMessage,
  onExecute,
}: Props) {
  return (
    <section className="rounded-[28px] border border-slate-200 bg-white/88 p-6 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
      <div className="border-b border-slate-200 pb-5">
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">Execution</p>
        <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950">실행 상태</h2>
      </div>

      <div className="mt-5 space-y-4">
        {steps.map((step, index) => (
          <article key={step.id} className={["rounded-3xl border p-5 transition-all duration-300", stepTone(index, activeIndex, started, completed)].join(" ")}>
            <div className="flex items-start gap-4">
              {indicator(index, activeIndex, started, completed)}
              <div className="min-w-0">
                <h3 className="text-base font-semibold text-slate-950">{step.label}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-600">{step.description}</p>
              </div>
            </div>
          </article>
        ))}
      </div>

      {errorMessage ? (
        <div className="mt-5 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {errorMessage}
        </div>
      ) : null}

      <div className="mt-6 flex justify-end">
        <button
          type="button"
          disabled={isSubmitting || completed}
          onClick={onExecute}
          className="rounded-full bg-sky-500 px-5 py-3 text-sm font-semibold text-white disabled:bg-slate-300"
        >
          {completed ? "리포트 이동 중..." : isSubmitting ? "검사 진행 중..." : "스캔 시작"}
        </button>
      </div>
    </section>
  );
}

export default RunExecutionPanel;
