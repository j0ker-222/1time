import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Button, Form, InputGroup } from "react-bootstrap";

import { copyText } from "../lib/clipboard.js";

export default function ShowNewLink() {
  const navigate = useNavigate();
  const { state } = useLocation();
  const [copied, setCopied] = useState(false);

  const newLink =
    state && state.randomString && state.newId
      ? `${window.location.origin}/v/#${state.randomString}${state.newId}`
      : "";

  async function copy() {
    if (!newLink) return;
    try {
      await copyText(newLink);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="Center">
      <InputGroup className="mb-3">
        <InputGroup.Text>Secret one-time link:</InputGroup.Text>
        <Form.Control type="text" value={newLink} readOnly onFocus={(e) => e.target.select()} onClick={copy} />
      </InputGroup>
      <div className="d-flex justify-content-center gap-2">
        <Button variant="primary" size="lg" onClick={() => navigate("/")}>
          Create new
        </Button>
        <Button variant="success" size="lg" onClick={copy} disabled={!newLink}>
          {copied ? "Copied" : "Copy to clipboard"}
        </Button>
      </div>
      <p className="small mt-gap">
        This secret one-time link works only once. Once it's open the content will be DELETED. The Message was
        encrypted, so it's impossible for us to read it.
      </p>
    </div>
  );
}
