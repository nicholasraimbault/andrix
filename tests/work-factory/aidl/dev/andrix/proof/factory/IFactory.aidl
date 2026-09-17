// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.factory;
import dev.andrix.proof.factory.FactoryState;
import dev.andrix.proof.factory.IWork;
// Fixed lab controls. Not a production work API or arbitrary privileged launcher.
interface IFactory {
    FactoryState observe();
    IWork create(long requestId, boolean blockAllocator);
    @nullable IWork find(long requestId);
    boolean unblockAllocator(long managerId);
    oneway void crash(long managerId);
    oneway void finish(long managerId);
}
