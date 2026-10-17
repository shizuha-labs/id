import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import Login from './pages/Login'
import Register from './pages/Register'
import Account from './pages/Account'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import PendingApproval from './pages/PendingApproval'
import OAuthAuthorize from './pages/OAuthAuthorize'
import GoogleCallback from './pages/GoogleCallback'
import StepUpEnrollConfirm from './pages/StepUpEnrollConfirm'
import Upgrade from './pages/Upgrade'

// Get base path from Vite config (e.g., "/id" when deployed in unified stack)
const basename = import.meta.env.BASE_URL?.replace(/\/$/, '') || ''

// Protected route wrapper - requires authentication
function RequireAuth({ children }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-600"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    // Redirect to login with current path as continue URL
    const continueUrl = window.location.pathname + window.location.search
    return <Navigate to={`/login?continue=${encodeURIComponent(continueUrl)}`} replace />
  }

  return children
}

// Root redirect - sends authenticated users to account, unauthenticated to login
function RootRedirect() {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-600"></div>
      </div>
    )
  }

  if (isAuthenticated) {
    return <Navigate to="/account" replace />
  }

  return <Navigate to="/login" replace />
}

function App() {
  return (
    <BrowserRouter basename={basename}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/accounts/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/pending-approval" element={<PendingApproval />} />
          <Route path="/step-up/enroll/confirm" element={<StepUpEnrollConfirm />} />
          <Route
            path="/account"
            element={
              <RequireAuth>
                <Account />
              </RequireAuth>
            }
          />
          <Route
            path="/upgrade"
            element={
              <RequireAuth>
                <Upgrade />
              </RequireAuth>
            }
          />
          <Route path="/oauth/authorize" element={<OAuthAuthorize />} />
          <Route path="/auth/google" element={<GoogleCallback />} />
          <Route path="/" element={<RootRedirect />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
