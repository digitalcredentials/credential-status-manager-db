import { StatusListCapacityError } from './errors.js';

export class IndexAllocator {
  private readonly availableIndices: number[];
  private readonly availableIndexBuffer: number;

  constructor(allocatedIndices: number[], maxIndex: number, availableIndexBuffer: number) {
    const allocatedIndexSet = new Set<number>(allocatedIndices);
    const availableIndices = [];
    for (let i = 1; i <= maxIndex; i++) {
      if (!allocatedIndexSet.has(i)) {
        availableIndices.push(i);
      }
    }
    this.availableIndices = availableIndices;
    this.availableIndexBuffer = availableIndexBuffer;
  }

  getAvailableIndex(): number {
    if (this.getAvailableIndexCounter() <= this.availableIndexBuffer) {
      throw new StatusListCapacityError();
    }
    const availableIndexPosition = Math.floor(Math.random() * this.availableIndices.length);
    const availableIndex = this.availableIndices[availableIndexPosition];
    this.availableIndices.splice(availableIndexPosition, 1);
    return availableIndex;
  }

  getAvailableIndexCounter(): number {
    return this.availableIndices.length;
  }
}
