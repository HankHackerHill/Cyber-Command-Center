import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { downloadVerifiedArtifact, getFindingEvidence, isEngagementId, type Finding } from "../../api/client";
import { useWorkspace } from "../../workspace";
import "./vault.css";

const EMPTY_FINDINGS: Finding[] = [];
const FINDING_ID_LIMIT = 512;

function statusLabel(status: Finding["status"]): string {
  const value = (status ?? "HYPOTHESIS").toLowerCase().replaceAll("_", " ");
  return value[0].toUpperCase() + value.slice(1);
}

type Verification =
  | { kind: "pending"; digest: string }
  | { kind: "verified"; digest: string; url: string; size: number }
  | { kind: "error"; digest: string };

function LinkedArtifacts({ engagementId, findingId }: { engagementId: string; findingId: string }) {
  const links = useQuery({
    queryKey: ["linked-evidence", engagementId, findingId],
    queryFn: ({ signal }) => getFindingEvidence(engagementId, findingId, signal),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const [verification, setVerification] = useState<Verification | null>(null);
  const inFlight = useRef<AbortController | null>(null);
  const objectUrl = useRef<string | null>(null);

  useEffect(() => () => {
    inFlight.current?.abort();
    if (objectUrl.current) URL.revokeObjectURL(objectUrl.current);
    objectUrl.current = null;
  }, []);

  async function verify(digest: string) {
    if (inFlight.current) return;
    if (objectUrl.current) {
      URL.revokeObjectURL(objectUrl.current);
      objectUrl.current = null;
    }
    const controller = new AbortController();
    inFlight.current = controller;
    setVerification({ kind: "pending", digest });
    try {
      const verified = await downloadVerifiedArtifact(digest, controller.signal);
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(verified);
      objectUrl.current = url;
      setVerification({ kind: "verified", digest, url, size: verified.size });
    } catch {
      if (!controller.signal.aborted) setVerification({ kind: "error", digest });
    } finally {
      if (inFlight.current === controller) inFlight.current = null;
    }
  }

  return <section className="panel" aria-labelledby="artifacts-heading">
    <div className="panel-head">
      <h2 id="artifacts-heading">Linked artifacts</h2>
      {!!links.data && <span className="pill">{links.data.length} {links.data.length === 1 ? "artifact" : "artifacts"}</span>}
    </div>
    <p className="vault-finding-hint">Finding <code className="mono">{findingId}</code></p>
    {links.isPending && <p role="status" className="muted">Loading finding evidence…</p>}
    {links.isError && <div className="notice" role="alert">
      <p>The evidence service could not return links for this finding.</p>
      <button type="button" className="button button--secondary" onClick={() => void links.refetch()}>Retry evidence lookup</button>
    </div>}
    {links.data?.length === 0 && <p className="muted">This finding has no linked artifacts.</p>}
    {links.data && links.data.length > 0 && <ul className="artifact-list">
      {links.data.map((artifact, index) => {
        const result = verification?.digest === artifact.sha256 ? verification : null;
        return <li key={artifact.sha256} className="artifact-item">
          <div className="artifact-heading">
            <h3>{`Artifact ${index + 1}`}</h3>
            {result?.kind === "verified" && <span className="pill" role="status">SHA-256 verified</span>}
          </div>
          <dl className="artifact-digest">
            <dt>SHA-256</dt><dd className="mono">{artifact.sha256}</dd>
          </dl>
          <div className="artifact-actions">
            {result?.kind === "verified" ? <>
              <a className="button button--primary" href={result.url} download={`${artifact.sha256}.bin`}>Download verified artifact</a>
              <span className="muted">{result.size.toLocaleString()} bytes</span>
            </> : <button className="button button--secondary" type="button"
              disabled={verification?.kind === "pending"} onClick={() => void verify(artifact.sha256)}>
              {result?.kind === "pending" ? "Verifying…" : "Verify SHA-256"}
            </button>}
          </div>
          {result?.kind === "error" && <p className="notice" role="alert">Artifact verification failed. Download is blocked.</p>}
        </li>;
      })}
    </ul>}
  </section>;
}

function VaultContents({ engagementId, live, findings }: { engagementId: string; live: boolean; findings: Finding[] }) {
  const [input, setInput] = useState("");
  const [findingId, setFindingId] = useState("");
  const canLookUp = live && isEngagementId(engagementId) && input.trim().length > 0;
  function find(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (canLookUp) setFindingId(input);
  }
  return <div className="vault-columns">
    <section className="panel" aria-labelledby="finding-lookup">
      <div className="panel-head"><h2 id="finding-lookup">Find a finding</h2></div>
      <form className="vault-lookup" onSubmit={find}>
        <label className="field">Finding ID
          <input value={input} maxLength={FINDING_ID_LIMIT} disabled={!live} required onChange={(event) => {
            setInput(event.currentTarget.value);
            setFindingId("");
          }} />
        </label>
        <button className="button button--primary" type="submit" disabled={!canLookUp}>Find evidence</button>
      </form>
      {findings.length > 0 && <div className="vault-snapshot">
        <h3>Findings in snapshot</h3>
        <ul>{findings.map((finding) => <li key={finding.id}>
          <button className="vault-find-item" type="button" disabled={!live} onClick={() => {
            setInput(finding.id);
            setFindingId(finding.id);
          }}>
            <span>{finding.title}</span><small className="muted">{statusLabel(finding.status)}</small>
          </button>
        </li>)}</ul>
      </div>}
    </section>
    {live && findingId ? <LinkedArtifacts key={findingId} engagementId={engagementId} findingId={findingId} /> :
      <section className="panel vault-empty" aria-labelledby="artifacts-heading">
        <div className="panel-head"><h2 id="artifacts-heading">Linked artifacts</h2></div>
        <p className="muted">{live ? "Choose a finding or enter its ID to retrieve linked evidence." :
          "Attach a live engagement to retrieve finding evidence."}</p>
      </section>}
  </div>;
}

export function VaultRoute() {
  const { engagementId, mode, snapshot } = useWorkspace();
  return <div className="page">
    <header className="page-heading"><h1>Evidence vault</h1>
      <p className="lede">Look up linked artifacts and verify their contents before download.</p>
    </header>
    <VaultContents key={`${mode}:${engagementId}`} live={mode === "live"} engagementId={engagementId}
      findings={snapshot?.findings ?? EMPTY_FINDINGS} />
  </div>;
}
