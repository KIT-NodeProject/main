import type { CommonConfig } from "../../types/scan";

type Props = {
  common: CommonConfig;
  errorMessage: string;
  onPatch: (patch: Partial<CommonConfig>) => void;
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void;
};

function CommonForm({ common, errorMessage, onPatch, onSubmit }: Props) {
  return (
    <section className="rounded-[28px] border border-sky-100 bg-white/88 p-6 shadow-[0_20px_70px_rgba(148,163,184,0.18)]">
      <form className="space-y-6" onSubmit={onSubmit}>
        <div className="grid gap-4">
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-700">Base URL</span>
            <input
              className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-sky-400/50"
              placeholder="https://example.com"
              value={common.baseUrl}
              onChange={(event) => onPatch({ baseUrl: event.target.value })}
            />
          </label>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-700">로그인 상태</p>
              <p className="text-xs text-slate-500">
                로그인 후 점검이면 Cookie 또는 Authorization 값을 입력합니다.
              </p>
            </div>

            <div className="inline-flex rounded-full border border-slate-200 bg-slate-50 p-1">
              <button
                type="button"
                onClick={() =>
                  onPatch({
                    loginRequired: false,
                    authMode: "none",
                    cookieValue: "",
                    authorizationValue: "",
                  })
                }
                className={[
                  "rounded-full px-4 py-2 text-sm transition",
                  !common.loginRequired
                    ? "bg-emerald-100 text-emerald-900"
                    : "text-slate-500 hover:text-slate-900",
                ].join(" ")}
              >
                비로그인
              </button>

              <button
                type="button"
                onClick={() =>
                  onPatch({
                    loginRequired: true,
                    authMode: common.authMode === "none" ? "cookie" : common.authMode,
                  })
                }
                className={[
                  "rounded-full px-4 py-2 text-sm transition",
                  common.loginRequired
                    ? "bg-amber-100 text-amber-900"
                    : "text-slate-500 hover:text-slate-900",
                ].join(" ")}
              >
                로그인 필요
              </button>
            </div>
          </div>

          {common.loginRequired ? (
            <div className="grid gap-4 rounded-3xl border border-slate-200 bg-slate-50/80 p-4">
              <div>
                <p className="text-sm font-medium text-slate-700">로그인 후 요청 값</p>
                <p className="mt-1 text-xs text-slate-500">
                  브라우저 개발자 도구에서 확인한 Cookie 또는 Authorization 값을 넣습니다.
                </p>
              </div>

              <label className="space-y-2">
                <span className="text-sm font-medium text-slate-700">Cookie</span>
                <textarea
                  className="min-h-[96px] w-full resize-y rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-sky-400/50"
                  placeholder="sessionid=abc123; csrftoken=xyz"
                  value={common.cookieValue}
                  onChange={(event) =>
                    onPatch({
                      cookieValue: event.target.value,
                      authMode: event.target.value.trim() ? "cookie" : common.authMode,
                    })
                  }
                />
                <p className="text-xs text-slate-500">
                  예: sessionid=abc123; csrftoken=xyz
                </p>
              </label>

              <label className="space-y-2">
                <span className="text-sm font-medium text-slate-700">Authorization</span>
                <input
                  className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-sky-400/50"
                  placeholder="Bearer eyJ..."
                  value={common.authorizationValue}
                  onChange={(event) =>
                    onPatch({
                      authorizationValue: event.target.value,
                      authMode: event.target.value.trim() ? "bearer" : common.authMode,
                    })
                  }
                />
                <p className="text-xs text-slate-500">
                  예: Bearer eyJ...
                </p>
              </label>
            </div>
          ) : null}
        </div>

        {errorMessage ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            {errorMessage}
          </div>
        ) : null}

        <div className="flex justify-end">
          <button
            type="submit"
            className="inline-flex items-center justify-center rounded-full bg-sky-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-sky-600"
          >
            엔드포인트 설정
          </button>
        </div>
      </form>
    </section>
  );
}

export default CommonForm;