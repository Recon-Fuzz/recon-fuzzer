'use client';

import { cn } from '@/lib/utils';

type Status = 'success' | 'warning' | 'error' | 'info' | 'neutral';

interface StatusIndicatorProps {
  status: Status;
  label?: string;
  pulse?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const statusColors: Record<Status, string> = {
  success: 'bg-green-500',
  warning: 'bg-yellow-500',
  error: 'bg-red-500',
  info: 'bg-blue-500',
  neutral: 'bg-zinc-500',
};

const sizeClasses = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-2.5 h-2.5',
};

export function StatusIndicator({
  status,
  label,
  pulse = false,
  size = 'md',
  className,
}: StatusIndicatorProps) {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span
        className={cn(
          'rounded-full',
          statusColors[status],
          sizeClasses[size],
          pulse && 'animate-pulse'
        )}
      />
      {label && <span className="text-xs text-zinc-400">{label}</span>}
    </div>
  );
}

interface ConnectionStatusProps {
  connected: boolean;
  connecting?: boolean;
}

export function ConnectionStatus({
  connected,
  connecting,
}: ConnectionStatusProps) {
  if (connecting) {
    return (
      <StatusIndicator status="warning" label="Connecting..." pulse />
    );
  }

  if (connected) {
    return <StatusIndicator status="success" label="Connected" />;
  }

  return <StatusIndicator status="error" label="Disconnected" />;
}
