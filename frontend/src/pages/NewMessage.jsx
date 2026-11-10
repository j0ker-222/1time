import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Alert, Button, Form } from "react-bootstrap";

import { generatePassword } from "../lib/crypto.js";
import { deriveKeys, encrypt, fragment, newLinkKey } from "../lib/cryptoV2.js";
import { saveSecret } from "../lib/api.js";

const DEFAULT_DAYS = 7;

export default function NewMessage() {
  const navigate = useNavigate();
  const [secretMessage, setSecretMessage] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [duration, setDuration] = useState(String(DEFAULT_DAYS));
  const [needOptions, setNeedOptions] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  // Generated once, not on every render.
  const [randomPasswords] = useState(() => Array.from({ length: 4 }, generatePassword));

  async function handleSubmit(event) {
    event.preventDefault();
    setIsLoading(true);
    setError("");
    try {
      const linkKey = newLinkKey();
      const keys = await deriveKeys(linkKey, secretKey);
      const payload = await encrypt(keys, secretMessage);
      const days = parseInt(duration, 10) || DEFAULT_DAYS;
      const res = await saveSecret(payload, keys.token, days * 86400);
      if (res.status === "ok") {
        navigate("/new", { state: { fragment: fragment(linkKey, res.newId) } });
        return;
      }
      setError("Could not save the message. Please try again.");
    } catch {
      setError("The server is not available. Please try again later.");
    }
    setIsLoading(false);
  }

  return (
    <div className="Left">
      <Form onSubmit={handleSubmit}>
        <Form.Group controlId="secretMessage" className="mb-3">
          <Form.Label>One-time Message</Form.Label>
          <Form.Control
            autoFocus
            as="textarea"
            size="lg"
            rows={4}
            placeholder="All content will be encrypted with the uniq key on the client side."
            value={secretMessage}
            onChange={(e) => setSecretMessage(e.target.value)}
          />
        </Form.Group>

        {needOptions && (
          <div className="mb-3">
            <Form.Group controlId="secretKey" className="mb-2">
              <Form.Label>Additional Secret Key:</Form.Label>
              <Form.Control
                type="text"
                placeholder="Secret Key"
                autoComplete="off"
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
              />
            </Form.Group>
            <Form.Group controlId="duration">
              <Form.Label>Keep message for:</Form.Label>
              <Form.Select value={duration} onChange={(e) => setDuration(e.target.value)}>
                <option value="1">1 day</option>
                <option value="3">3 days</option>
                <option value="7">7 days</option>
                <option value="30">30 days</option>
              </Form.Select>
            </Form.Group>
          </div>
        )}

        {error && <Alert variant="danger">{error}</Alert>}

        <div className="d-flex justify-content-between mb-3">
          <Button variant="outline-secondary" onClick={() => setNeedOptions(!needOptions)}>
            Options
          </Button>
          <Button variant="success" size="lg" type="submit" disabled={secretMessage.length === 0 || isLoading}>
            {isLoading ? "Loading..." : "Get a link"}
          </Button>
        </div>

        <div className="small">
          For your convenience, here are a few strong random passwords:
          <div className="passwords">
            {randomPasswords.map((p) => (
              <div key={p}>{p}</div>
            ))}
          </div>
        </div>
        <p className="small mt-gap">
          Send passwords, one-time tokens, private messages or any sensitive data with strongly encrypted one-time
          link. When the user opens the link content is destroyed. We don't have access to the stored data, because
          it's encrypted on the client side with one-time password. The link is available for up to {duration} {duration === "1" ? "day" : "days"}.
        </p>
      </Form>
    </div>
  );
}
