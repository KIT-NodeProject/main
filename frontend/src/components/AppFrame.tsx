import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

type Props = {
  eyebrow?: string;
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
};

const NAV_ITEMS = [
  { to: "/setup", label: "공통 입력" },
  { to: "/endpoint", label: "엔드포인트" },
  { to: "/run", label: "실행" },
  { to: "/report", label: "리포트" },
];

function AppFrame({ eyebrow, title, description, actions, children }: Props) {
  return (
    <div className="min-h-screen px-4 py-6 text-slate-900 sm:px-6 lg:px-10">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
        <header className="overflow-hidden rounded-[32px] border border-sky-100 bg-white/80 shadow-[0_24px_80px_rgba(148,163,184,0.25)] backdrop-blur">
          <div className="flex flex-col gap-6 border-b border-slate-200 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-400 via-cyan-300 to-amber-200 text-base font-bold text-slate-900">
                  N
                </div>
                <div>
                  <p className="text-lg font-semibold tracking-[-0.03em] text-slate-950">
                    Node
                  </p>
                  {eyebrow ? (
                    <p className="text-xs font-semibold uppercase tracking-[0.28em] text-sky-700/70">
                      {eyebrow}
                    </p>
                  ) : null}
                </div>
              </div>
              {title || description ? (
                <div className="space-y-2">
                  {title ? (
                    <h1 className="max-w-3xl text-3xl font-semibold tracking-[-0.04em] text-slate-950 sm:text-4xl">
                      {title}
                    </h1>
                  ) : null}
                  {description ? (
                    <p className="max-w-3xl text-sm leading-6 text-slate-600 sm:text-base">
                      {description}
                    </p>
                  ) : null}
                </div>
              ) : null}
            </div>
            {actions ? <div className="flex items-center gap-3">{actions}</div> : null}
          </div>

          <nav className="flex flex-wrap gap-2 px-4 py-4 sm:px-6">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  [
                    "rounded-full border px-4 py-2 text-sm font-medium transition",
                    isActive
                      ? "border-sky-300 bg-sky-100 text-sky-900"
                      : "border-slate-200 bg-slate-50 text-slate-600 hover:border-sky-200 hover:bg-white",
                  ].join(" ")
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </header>

        <main>{children}</main>
      </div>
    </div>
  );
}

export default AppFrame;
