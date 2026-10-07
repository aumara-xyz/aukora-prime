import { copyWire } from './expansion.mjs';
import { freezeData } from './bytes.mjs';
import { readPinnedData } from './pinned-data.mjs';

const source = readPinnedData('geometry_index_table_v1.json');
const phi = (1 + Math.sqrt(5)) / 2;
const approximate = ({ a, b }) => a[0] / a[1] + (b[0] / b[1]) * phi;

// Coordinate approximation is for drawing only. Indices always come from DATA.
export const GEOMETRY = freezeData({
  centreIndex: source.centre_index,
  centreValue: source.centre_fixed_value,
  mutableIndices: [...source.mutable_indices],
  points: source.points.map(point => ({
    globalIndex: point.global_index,
    xyz: point.coordinates.map(approximate),
    multiplicity: point.multiplicity,
  })),
  cubes: source.cubes.map(cube => ({
    cubeId: cube.cube_id,
    slots: cube.slots.map(slot => slot.global_index),
    edges: cube.edges_global_indices.map(edge => [...edge]),
  })),
});

export function projectGeometry(wire110) {
  const wire = copyWire(wire110);
  const cells111 = Array(111).fill(0);
  for (let i = 0; i < 110; i += 1) cells111[GEOMETRY.mutableIndices[i]] = wire[i] - 1;
  const cubes = GEOMETRY.cubes.map(cube => cube.slots.map(index => cells111[index]));
  return freezeData({ cells111, cubes });
}
