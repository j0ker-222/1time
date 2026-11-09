import { useNavigate } from "react-router-dom";
import { Button } from "react-bootstrap";

export default function NotFound() {
  const navigate = useNavigate();
  return (
    <div className="Center">
      <p className="text-danger">Page not found.</p>
      <Button size="lg" variant="primary" onClick={() => navigate("/")}>
        Create New
      </Button>
    </div>
  );
}
