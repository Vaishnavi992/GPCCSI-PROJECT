import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout        from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import Login      from './pages/Login'
import Signup     from './pages/Signup'
import Dashboard  from './pages/Dashboard'
import URLScanner from './pages/URLScanner'
import BulkScanner from './pages/BulkScanner'
import QRScanner  from './pages/QRScanner'
import History    from './pages/History'
import Analytics  from './pages/Analytics'
import Report     from './pages/Report'

const P = ({ children }) => (
  <ProtectedRoute><Layout>{children}</Layout></ProtectedRoute>
)

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"          element={<Login/>} />
        <Route path="/signup"         element={<Signup/>} />
        <Route path="/"               element={<Navigate to="/dashboard" replace/>} />
        <Route path="/dashboard"      element={<P><Dashboard/></P>} />
        <Route path="/scan/url"       element={<P><URLScanner/></P>} />
        <Route path="/scan/bulk"      element={<P><BulkScanner/></P>} />
        <Route path="/scan/qr"        element={<P><QRScanner/></P>} />
        <Route path="/history"        element={<P><History/></P>} />
        <Route path="/analytics"      element={<P><Analytics/></P>} />
        <Route path="/report/:id"     element={<P><Report/></P>} />
        <Route path="*"               element={<Navigate to="/dashboard" replace/>} />
      </Routes>
    </BrowserRouter>
  )
}
