import { useState } from 'react';
import AttackerModal from './AttackerModal';

interface IPLinkProps {
  ip: string;
  className?: string;
}

export default function IPLink({ ip, className = '' }: IPLinkProps) {
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      <button
        onClick={() => setShowModal(true)}
        className={`ip-link font-mono text-neon-blue hover:text-neon-green ${className}`}
      >
        {ip}
      </button>

      {showModal && (
        <AttackerModal ip={ip} onClose={() => setShowModal(false)} />
      )}
    </>
  );
}

