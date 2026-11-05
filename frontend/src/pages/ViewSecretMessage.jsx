import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Alert, Button, Card, Form } from "react-bootstrap";

import { decryptMessage, hashKey, parseLink } from "../lib/crypto.js";
import { getSecret } from "../lib/api.js";
import { copyText } from "../lib/clipboard.js";

export default function ViewSecretMessage() {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);
  const [secretMessage, setSecretMessage] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [needSecretKey, setNeedSecretKey] = useState(false);
  const [isWrongKey, setIsWrongKey] = useState(false);
  const [isNoMessage, setIsNoMessage] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setIsLoading(true);
    setIsWrongKey(false);
    setError("");

    const link = parseLink(window.location.href);
    if (!link) {
      setIsLoading(false);
      setIsNoMessage(true);
      return;
    }
    const passphrase = secretKey + link.randomKey;
    try {
      const res = await getSecret(link.id, hashKey(passphrase));
      if (res.status === "ok" && res.cryptedMessage) {
        setSecretMessage(decryptMessage(res.cryptedMessage, passphrase));
        // Drop the key from the address bar and history once it is used.
        window.history.replaceState(null, "", "/v/");
      } else if (res.status === "wrong key") {
        setIsWrongKey(true);
        setNeedSecretKey(true);
      } else if (res.status === "no message") {
        setIsNoMessage(true);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } catch {
      setError("The server is not available. Please try again later.");
    }
    setIsLoading(false);
  }

  async function copy() {
    try {
      await copyText(secretMessage);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const hasMessage = secretMessage.length > 0;
  const showReadForm = !hasMessage && !isNoMessage;

  return (
    <div className="Left">
      {showReadForm && (
        <Form onSubmit={handleSubmit}>
          <p>You are about to read the secret message. Once you read it will be destroyed.</p>
          {needSecretKey && (
            <Form.Group controlId="secretKey" className="mb-3">
              <Form.Label>Secret Key</Form.Label>
              <Form.Control
                size="lg"
                type="text"
                placeholder="Secret Key"
                autoComplete="off"
                value={secretKey}
                isInvalid={isWrongKey}
                onChange={(e) => setSecretKey(e.target.value)}
              />
              <Form.Control.Feedback type="invalid">
                {secretKey ? "Wrong secret key." : "This message is protected with an additional secret key."}
              </Form.Control.Feedback>
            </Form.Group>
          )}
          {error && <Alert variant="danger">{error}</Alert>}
          <div className="Center">
            <Button size="lg" variant="success" type="submit" disabled={isLoading}>
              {isLoading ? "Loading..." : "Read the message"}
            </Button>
          </div>
        </Form>
      )}

      {hasMessage && (
        <Card className="mb-3">
          <Card.Header as="h3" className="h6">
            One-time message:
          </Card.Header>
          <Card.Body>
            <pre className="secret-text">{secretMessage}</pre>
          </Card.Body>
          <Card.Footer className="text-center">
            <Button size="sm" variant="success" onClick={copy}>
              {copied ? "Copied" : "Copy to clipboard"}
            </Button>
          </Card.Footer>
        </Card>
      )}

      {(hasMessage || isNoMessage) && (
        <div className="Center">
          <p className="small">{hasMessage ? "Message was destroyed." : "Message was destroyed or never existed."}</p>
          <Button size="lg" variant="primary" onClick={() => navigate("/")}>
            Create New
          </Button>
        </div>
      )}
    </div>
  );
}
