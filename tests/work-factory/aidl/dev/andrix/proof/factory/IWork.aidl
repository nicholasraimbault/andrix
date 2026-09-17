// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.factory;
import dev.andrix.proof.factory.WorkState;
interface IWork {
    WorkState observe();
    boolean hold(long workId);
    boolean release(long workId);
    oneway void stop(long workId, boolean crashGuardian);
}
