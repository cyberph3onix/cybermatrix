export function Section({
  id,
  title,
  intro,
  children,
}: {
  id: string;
  title: string;
  intro?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="mt-10">
      <h2 id={id} className="text-xl font-semibold">
        {title}
      </h2>
      {intro && <div className="mt-1 max-w-prose text-sm text-muted">{intro}</div>}
      <div className="mt-4">{children}</div>
    </section>
  );
}
