import { BrowserRouter, Routes, Route } from 'react-router-dom'
import DashboardPage from './pages/DashboardPage'
import ThreatDetailPage from './pages/ThreatDetailPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/threat/:threatId" element={<ThreatDetailPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
