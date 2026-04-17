'use client';

import { cn } from '@/lib/utils';

interface PanelProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
  actions?: React.ReactNode;
}

export function Panel({ children, className, title, actions }: PanelProps) {
  return (
    <div className={cn('flex flex-col h-full bg-zinc-900', className)}>
      {title && (
        <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
          <h3 className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
            {title}
          </h3>
          {actions && <div className="flex items-center gap-1">{actions}</div>}
        </div>
      )}
      {title ? (
        <div className="flex-1 overflow-auto min-h-0">{children}</div>
      ) : (
        children
      )}
    </div>
  );
}

interface PanelHeaderProps {
  children: React.ReactNode;
  className?: string;
}

export function PanelHeader({ children, className }: PanelHeaderProps) {
  return (
    <div
      className={cn(
        'flex items-center justify-between px-3 py-2 border-b border-zinc-800',
        className
      )}
    >
      {children}
    </div>
  );
}

interface PanelContentProps {
  children: React.ReactNode;
  className?: string;
  scrollable?: boolean;
}

export function PanelContent({
  children,
  className,
  scrollable = true,
}: PanelContentProps) {
  return (
    <div
      className={cn(
        'flex-1 min-h-0', // min-h-0 is crucial for flex children to shrink properly
        scrollable ? 'overflow-auto' : 'overflow-hidden',
        className
      )}
    >
      {children}
    </div>
  );
}
