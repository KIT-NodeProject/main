import { useState } from "react";
import { useNavigate } from "react-router-dom";
import AppFrame from "../components/AppFrame";
import CommonForm from "../features/flow/CommonForm";
import FlowCards from "../features/flow/FlowCards";
import { useScanStore } from "../store/scanStore";

function SetupPage() {
  const navigate = useNavigate();
  const common = useScanStore((state) => state.common);
  const setCommon = useScanStore((state) => state.setCommon);
  const [errorMessage, setErrorMessage] = useState("");

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const parsedUrl = new URL(common.baseUrl.trim());
      if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        throw new Error("invalid_protocol");
      }
    } catch {
      setErrorMessage("Base URL은 http 또는 https로 시작해야 합니다.");
      return;
    }
    setCommon({ baseUrl: common.baseUrl.trim(), authMode: common.loginRequired ? common.authMode : "none" });
    setErrorMessage("");
    navigate("/endpoint");
  };

  return (
    <AppFrame eyebrow="Security Scanner">
      <div className="space-y-6">
        <CommonForm common={common} errorMessage={errorMessage} onPatch={setCommon} onSubmit={handleSubmit} />
        <FlowCards />
      </div>
    </AppFrame>
  );
}

export default SetupPage;
