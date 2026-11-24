import type { ReactNode } from 'react'

export function PageHeading({ title, description, category, actions }: {
  title: string; description?: string; category?: string; actions?: ReactNode
}) {
  return <header className="page-heading">
    <div>
      {category && <p className="eyebrow">{category}</p>}
      <h1>{title}</h1>
      {description && <p className="lede">{description}</p>}
    </div>
    {actions && <div className="heading-actions">{actions}</div>}
  </header>
}

export function Pill({ children, tone = 'neutral' }: {
  children: ReactNode; tone?: 'neutral' | 'accent' | 'success' | 'warning' | 'danger'
}) {
  return <span className={`pill pill--${tone}`}>{children}</span>
}

export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return <div className="empty-state"><h3>{title}</h3><p>{children}</p></div>
}
