import { Navigate, Route, Routes } from "react-router-dom";
import EndpointPage from "./pages/EndpointPage";
import ReportPage from "./pages/ReportPage";
import RunPage from "./pages/RunPage";
import SetupPage from "./pages/SetupPage";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate replace to="/setup" />} />
      <Route path="/setup" element={<SetupPage />} />
      <Route path="/endpoint" element={<EndpointPage />} />
      <Route path="/run" element={<RunPage />} />
      <Route path="/report" element={<ReportPage />} />
      <Route path="*" element={<Navigate replace to="/setup" />} />
    </Routes>
  );
}

export default App;
