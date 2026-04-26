export default function VMShieldLogo({ className = "w-10 h-10" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <path
        d="M20 2L6 8V18C6 26.5 11.5 34.5 20 38C28.5 34.5 34 26.5 34 18V8L20 2Z"
        stroke="currentColor"
        strokeWidth="1.5"
        fill="none"
      />
      <text
        x="20"
        y="25"
        fontSize="14"
        fontWeight="600"
        fill="currentColor"
        textAnchor="middle"
        fontFamily="system-ui, -apple-system, sans-serif"
      >
        VM
      </text>
    </svg>
  );
}
