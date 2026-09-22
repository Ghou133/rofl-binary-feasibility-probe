class EntityRegistry {
  constructor() {
    this.entities = new Map();
  }

  register(networkId, fields = {}) {
    if (networkId === null || networkId === undefined) throw new Error('networkId is required');
    const existing = this.entities.get(networkId) || {
      network_id: networkId,
      entity_type: 'unknown',
      champion: null,
      participant_id: null,
      team_id: null,
      player_identifier: null,
      attributed_champion: null,
      confidence: 'UNVERIFIED',
    };
    const merged = { ...existing, ...fields, network_id: networkId };
    this.entities.set(networkId, merged);
    return { ...merged };
  }

  resolve(networkId) {
    const entity = this.entities.get(networkId);
    return entity ? { ...entity } : null;
  }

  attributeSource(networkId) {
    const entity = this.resolve(networkId);
    if (!entity) return { raw_source_entity: null, attributed_champion: null, status: 'UNAVAILABLE' };
    return {
      raw_source_entity: entity,
      attributed_champion: entity.attributed_champion || (entity.entity_type === 'champion' ? entity.champion : null),
      status: entity.attributed_champion || entity.entity_type === 'champion' ? entity.confidence : 'UNVERIFIED',
    };
  }

  toJSON() {
    return [...this.entities.values()].sort((a, b) => Number(a.network_id) - Number(b.network_id));
  }
}

module.exports = { EntityRegistry };
