# SPDX-License-Identifier: Apache-2.0
import unittest
from scripts.proof.systemui_sessions import created_session, commit_observation, parent_sessions, require_state, READY

def row(identity=12345, package='com.android.systemui', ready='true', applied='false', failed='false', error=''):
    return f'sessionId = {identity}; appPackageName = {package}; isStaged = true; isReady = {ready}; isApplied = {applied}; isFailed = {failed}; errorMsg = {error};\n'

class Tests(unittest.TestCase):
    def test_create(self):
        self.assertEqual(created_session(0, 'Success: created install session [123]\n'), 123)
        for code,text in [(1,'Success: created install session [123]'),(0,'Success'),(0,'Success: created install session [0]'),(0,'Success: created install session [2147483648]'),(0,'Success: created install session [1]\nnoise')]:
            with self.assertRaises(ValueError):created_session(code,text)
    def test_ready_not_applied(self):
        records=parent_sessions(1,row())
        self.assertTrue(require_state(records,12345,'ready').ready)
        with self.assertRaises(ValueError):require_state(records,12345,'applied')
        applied=parent_sessions(1,row(ready='false',applied='true'))
        self.assertTrue(require_state(applied,12345,'applied').applied)
    def test_wraps(self):
        raw=row().strip()+row(456).strip()
        for width in [1,7,19,120]:
            wrapped='\n'.join(raw[n:n+width] for n in range(0,len(raw),width))
            self.assertEqual([r.identity for r in parent_sessions(1,wrapped)],[12345,456])
    def test_bad_listing_and_exit(self):
        for code,text in [(0,row()),(-1,row()),(255,row()),(1,'Failure [binder]'),(1,'sessionId = 1; not found'),(1,row()+row()),(1,row(ready='true',failed='true')),(1,row(error='unexpected;embedded delimiter'))]:
            with self.assertRaises(ValueError):parent_sessions(code,text)
        self.assertEqual(parent_sessions(1,''),[])
        with self.assertRaises(ValueError):require_state([],12345,'applied')
    def test_exact_package_and_id(self):
        for records,identity in [(parent_sessions(1,row()),999),(parent_sessions(1,row(package='other.app')),12345),(parent_sessions(1,row(package='null',ready='false')),12345)]:
            with self.assertRaises(ValueError):require_state(records,identity,'ready')
    def test_commit_ambiguity(self):
        self.assertEqual(commit_observation(0,READY+'\n'),'ready')
        self.assertEqual(commit_observation(0,'Success\n'),'accepted_without_readiness')
        timeout="Failure [timed out after 60000 ms]. Ending this command now but session is still being staged asynchronously. Use 'pm list staged-sessions' to check the session status later."
        self.assertEqual(commit_observation(1,timeout),'pending_after_timeout')
        for code,text in [(1,READY),(0,'Success\nnoise'),(1,'Error [-1] [failed]'),(-15,''),(0,'')]:
            self.assertEqual(commit_observation(code,text),'unknown')

if __name__=='__main__':unittest.main()
