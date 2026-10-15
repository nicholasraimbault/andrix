// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principalclosed;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.util.Log;

/** Any callback invalidates the preservation trial. Never requests replacement or rescheduling. */
public final class B2StateJobService extends JobService {
    private void unexpected(String callback) {
        Log.e("AndrixB2State", "ANDRIX_B2_UNEXPECTED_JOB_CALLBACK " + callback);
        try {
            StateFiles files = new StateFiles(this);
            // No parent creation. Missing state is itself a failure, not a setup opportunity.
            StateFiles.directory(files.deFiles); StateFiles.directory(files.deDir);
            StateFiles.newFile(files.sentinel, Contract.ascii("unexpected-job=" + callback + "\n"));
        } catch (Exception error) {
            Log.e("AndrixB2State", "ANDRIX_B2_CALLBACK_SENTINEL_FAILED " + error.getClass().getName());
        }
    }
    @Override public boolean onStartJob(JobParameters params) { unexpected("start"); return false; }
    @Override public boolean onStopJob(JobParameters params) { unexpected("stop"); return false; }
}
