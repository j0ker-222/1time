import { Route, Routes } from "react-router-dom";

import NewMessage from "./pages/NewMessage.jsx";
import ShowNewLink from "./pages/ShowNewLink.jsx";
import ViewSecretMessage from "./pages/ViewSecretMessage.jsx";
import NotFound from "./pages/NotFound.jsx";

export default function App() {
  return (
    <div className="App container">
      <Routes>
        <Route path="/" element={<NewMessage />} />
        <Route path="/index.html" element={<NewMessage />} />
        <Route path="/new" element={<ShowNewLink />} />
        <Route path="/v/*" element={<ViewSecretMessage />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </div>
  );
}
