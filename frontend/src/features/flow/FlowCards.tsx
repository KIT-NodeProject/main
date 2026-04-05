const FLOW_STEPS = [
  ["01", "공통 입력", "Base URL과 로그인 여부를 먼저 정리합니다."],
  ["02", "엔드포인트 설정", "요청 경로와 파라미터를 기준으로 검사 대상을 정합니다."],
  ["03", "진단 옵션 설정", "기술스택정보를 입력하고 추가 분석 기준을 정리합니다."],
  ["04", "실행 요청", "검사 진행 상태를 애니메이션으로 확인합니다."],
  ["05", "리포트 확인", "엔드포인트 기준 결과와 리포트를 한 화면에서 봅니다."],
] as const;

function FlowCards() {
  return (
    <section className="rounded-[28px] border border-sky-100 bg-white/80 p-6 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
      <div className="space-y-6">
        <p className="text-sm font-medium uppercase tracking-[0.24em] text-sky-700/80">Flow</p>
        <div className="grid gap-3 lg:grid-cols-5">
          {FLOW_STEPS.map(([step, title, copy]) => (
            <article
              key={step}
              className="rounded-2xl border border-slate-200 bg-gradient-to-br from-white to-sky-50 p-4"
            >
              <p className="text-xs font-semibold tracking-[0.3em] text-sky-700/70">{step}</p>
              <h3 className="mt-3 text-base font-semibold text-slate-950">{title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{copy}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export default FlowCards;
