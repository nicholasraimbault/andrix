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
        for code,text in [(0,row()),(-1,row()),(255,row()),(1,'Failure [binder]'),(1,'sessionId = 1; not found'),(1,row()+row()),(1,row(ready='true',failed='true'))]:
            with self.assertRaises(ValueError):parent_sessions(code,text)
        self.assertEqual(parent_sessions(1,''),[])
        with self.assertRaises(ValueError):require_state([],12345,'applied')
    def test_semicolons_in_failed_session_cause(self):
        cause='Reverting back to safe state. Reason for revert: Existing package com.android.systemui signatures do not match newer version; ignoring!'
        text=row(ready='false',failed='true',error=cause)+row(456)
        wrapped='\n'.join(text.replace('\n','')[n:n+120] for n in range(0,len(text.replace('\n','')),120))
        records=parent_sessions(1,wrapped)
        self.assertEqual(require_state(records,12345,'failed').error,cause)
        self.assertTrue(require_state(records,456,'ready').ready)
        self.assertTrue(intended_rejection('wrong-signer',cause))

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


from scripts.proof.systemui_sessions import historical_failure, intended_rejection

class HistoricalTests(unittest.TestCase):
    def dump(self, message, status=-7, installer=2000, package='com.android.systemui', applied='false'):
        body=(f'userId=0 mOriginalInstallerUid=2000 mInstallerUid={installer} '\
              f'mFinalStatus={status} mFinalMessage={message} mParentSessionId=-1 '\
              f'mSessionApplied={applied} mSessionFailed=true mSessionReady=false '\
              f'mAppPackageName={package} mInitialVerificationPolicy=0 ')
        return 'Historical install sessions:\n  Session 71:\n'+''.join('    '+body[n:n+116]+'\n' for n in range(0,len(body),116))+'Legacy install sessions:\n'
    def test_exact_historical_cause(self):
        text='New package has a different signature: com.android.systemui'
        found=historical_failure(0,self.dump(text),71)
        self.assertEqual(found.message,text)
        self.assertTrue(intended_rejection('wrong-signer',found.message))
    def test_reject_wrong_identity_principal_and_success(self):
        for text,ident in [(self.dump('error'),72),(self.dump('error',installer=0),71),(self.dump('error',status=1),71),(self.dump('error',package='other.app'),71),(self.dump('error',applied='true'),71),(self.dump('error').replace('Legacy install sessions:',''),71)]:
            with self.assertRaises(ValueError):historical_failure(0,text,ident)
    def test_io_error_is_not_a_signer_negative(self):
        text='INSTALL_FAILED_BAD_SIGNATURE: Failed to enable fs-verity to verify with idsig: Permission denied'
        self.assertFalse(intended_rejection('wrong-signer',text))
        self.assertFalse(intended_rejection('missing-sidecar',text))
        self.assertTrue(intended_rejection('missing-sidecar',"fs-verity not set up for system package update: APK doesn't have fs-verity: /data/app-staging/session_71/base.apk"))
    def test_absence_duplicate_truncation_or_command_failure_not_rejection(self):
        text=self.dump('error')
        for code,data in [(1,text),(0,''),(0,text.replace('  Session 71:', '  Session 71:\n  Session 71:')),(0,text.replace('mFinalStatus=', 'mFinalStatus=-7 mFinalStatus='))]:
            with self.assertRaises(ValueError):historical_failure(code,data,71)

if __name__=='__main__':unittest.main()
