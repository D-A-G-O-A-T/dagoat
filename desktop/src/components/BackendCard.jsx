/// One CatalogEntry as a selector card. Enabled rows are buttons; disabled rows are
/// non-interactive and show disabled_reason verbatim (no hardcoded copy).
export default function BackendCard({ entry, selected, onSelect }) {
  const tags = (
    <div className="backend-card__tags">
      <span className="backend-card__tag">{entry.isolation_class}</span>
      {(entry.honesty_tags ?? []).map((tag) => (
        <span key={tag} className="backend-card__tag">
          {tag}
        </span>
      ))}
    </div>
  );

  const body = (
    <>
      <h3 className="backend-card__title">{entry.display_name}</h3>
      <p className="backend-card__beneficiary muted">{entry.beneficiary}</p>
      {tags}
      <p className="backend-card__formula muted">{entry.formula}</p>
    </>
  );

  if (!entry.enabled) {
    return (
      <div className="backend-card backend-card--disabled" aria-disabled="true">
        {body}
        {entry.disabled_reason && (
          <p className="backend-card__caption status-warn">{entry.disabled_reason}</p>
        )}
      </div>
    );
  }

  return (
    <button
      type="button"
      className={`backend-card ${selected ? "backend-card--selected" : ""}`}
      onClick={() => onSelect(entry.id)}
      aria-pressed={selected}
    >
      {body}
    </button>
  );
}
