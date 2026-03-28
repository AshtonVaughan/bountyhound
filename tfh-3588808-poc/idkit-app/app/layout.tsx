export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ background: '#0a0a0a', color: '#e0e0e0', fontFamily: 'monospace', padding: '2rem' }}>
        {children}
      </body>
    </html>
  )
}
