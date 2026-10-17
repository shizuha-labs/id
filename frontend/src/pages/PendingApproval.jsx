import { Link } from 'react-router-dom'
import { Clock, ArrowLeft } from 'lucide-react'

export default function PendingApproval() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Shizuha ID
          </h1>
        </div>

        {/* Card */}
        <div className="card p-8 text-center">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center">
              <Clock className="h-8 w-8 text-yellow-600 dark:text-yellow-400" />
            </div>
          </div>

          <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
            Account Pending Approval
          </h2>

          <p className="text-gray-600 dark:text-gray-400 mb-6">
            Your account has been created and is waiting for administrator approval.
            You'll receive an email once your account has been reviewed.
          </p>

          <Link
            to="/login"
            className="inline-flex items-center gap-2 text-sm text-indigo-600 hover:text-indigo-500 dark:text-indigo-400 font-medium"
          >
            <ArrowLeft size={16} />
            Back to login
          </Link>
        </div>
      </div>
    </div>
  )
}
