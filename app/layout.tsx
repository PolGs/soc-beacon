import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import { Toaster } from 'sonner'

import './globals.css'

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' })
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jetbrains' })

export const metadata: Metadata = {
  title: 'SOC Beacon',
  description: 'AI-powered log enrichment and threat analysis platform',
  icons: {
    icon: '/favicon.ico',
    shortcut: '/favicon.ico',
  },
}

export const viewport: Viewport = {
  themeColor: '#0a0a0a',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans antialiased min-h-screen">
        {children}
        <Toaster
          theme="dark"
          toastOptions={{
            style: {
              background: 'hsl(0 0% 7%)',
              border: '1px solid hsl(0 0% 15%)',
              color: 'hsl(0 0% 95%)',
            },
          }}
        />
      </body>
    </html>
  )
}
