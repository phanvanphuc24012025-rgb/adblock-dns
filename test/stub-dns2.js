// Minimal stand-in for the dns2 package so the logic tests run without
// `npm install` and without a network. Only used by tests.
const Packet = {
  TYPE: { A: 1, AAAA: 28, HTTPS: 65, MX: 15 },
  CLASS: { IN: 1 },
  createResponseFromRequest: (r) => ({
    header: { rcode: 0 }, questions: r.questions, answers: [],
    toBuffer() { return Buffer.from(JSON.stringify({ rcode: this.header.rcode, answers: this.answers })); }
  }),
  parse: (buf) => JSON.parse(buf.toString())
};
class Client {
  async resolve(name, t) {
    if (name.startsWith('nx')) return { header: { rcode: 3 }, answers: [] };
    return { header: { rcode: 0 }, answers: [{ name, type: Packet.TYPE[t], ttl: 100, address: '1.2.3.4' }] };
  }
  async resolveA(name) { return this.resolve(name, 'A'); }
}
Client.Packet = Packet;
Client.createServer = () => ({ on() {}, listen: async () => {} });
module.exports = Client;
