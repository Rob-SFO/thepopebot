import './globals.css';
import { ThemeProvider, FeaturesProvider } from 'thepopebot/chat';
import { getOAuthTokenCount } from 'thepopebot/db/oauth-tokens';

export const metadata = {
  title: 'ThePopeBot',
  description: 'AI Agent',
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  viewportFit: 'cover',
};

function hasOAuthToken() {
  try {
    return getOAuthTokenCount() > 0;
  } catch {
    return false;
  }
}

const hasOAuth = hasOAuthToken() || !!process.env.CLAUDE_CODE_OAUTH_TOKEN;
const features = {
  codeWorkspace: hasOAuth,
  clusterWorkspace: hasOAuth,
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <FeaturesProvider features={features}>
          <ThemeProvider>
            {children}
          </ThemeProvider>
        </FeaturesProvider>
      </body>
    </html>
  );
}
