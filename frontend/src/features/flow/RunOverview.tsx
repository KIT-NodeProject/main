import type { CommonConfig, StackConfig } from "../../types/scan";

type Props = {
  common: CommonConfig;
  stack: StackConfig;
  endpointCount: number;
  hasEndpointScan: boolean;
  hasStackScan: boolean;
};

function RunOverview({ common, stack, endpointCount, hasEndpointScan, hasStackScan }: Props) {
  const cards = [
    ["Base URL", common.baseUrl || "-"],
    ["로그인", common.loginRequired ? common.authMode.toUpperCase() : "비로그인"],
    ["엔드포인트", hasEndpointScan ? `${endpointCount} requests` : "실행 안 함"],
    ["기술 스택", hasStackScan ? stack.stackName : "실행 안 함"],
  ];

  return (
    <section className="grid gap-4 lg:grid-cols-4">
      {cards.map(([label, value]) => (
        <article key={label} className="rounded-3xl border border-slate-200 bg-white/85 p-5">
          <p className="text-xs uppercase tracking-[0.28em] text-slate-500">{label}</p>
          <p className="mt-3 break-all text-lg font-semibold text-slate-950">{value}</p>
        </article>
      ))}
    </section>
  );
}

export default RunOverview;
