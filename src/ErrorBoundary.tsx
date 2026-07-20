import { Component, type ErrorInfo, type ReactNode } from "react";

interface State {
  error: Error | null;
}

/** Catches render-time errors so preview/dev shows a message instead of a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled render error:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="centered-form">
          <h2>Something went wrong</h2>
          <p className="error-text">{this.state.error.message}</p>
          <p className="muted">Check the browser console for details.</p>
        </div>
      );
    }
    return this.props.children;
  }
}
